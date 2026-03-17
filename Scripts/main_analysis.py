import os
import sys
import psutil
import platform
import datetime
import getpass
import socket
import base64
from io import BytesIO
import hashlib
import json
import warnings
import requests
from pathlib import Path
from collections import defaultdict
warnings.filterwarnings('ignore')
from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.metrics import classification_report, confusion_matrix
    import joblib
    import numpy as np
    import pandas as pd
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False
    print("WARNING: scikit-learn not available. ML features disabled.")
try:
    import cpuinfo
    CPUINFO_AVAILABLE = True
except Exception:
    CPUINFO_AVAILABLE = False
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders

SMTP_SENDER = os.getenv('TRIAGE_SMTP_SENDER', '')
SMTP_APP_PASSWORD = os.getenv('TRIAGE_SMTP_PASS', '')
SMTP_RECEIVER = os.getenv('TRIAGE_SMTP_RECEIVER', '')

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TOOLKIT_DIR = os.path.join(BASE_DIR, 'toolkit')
DATASETS_DIR = os.path.join(TOOLKIT_DIR, 'datasets')
os.makedirs(TOOLKIT_DIR, exist_ok=True)
os.makedirs(DATASETS_DIR, exist_ok=True)

MODEL_PATH = os.path.join(TOOLKIT_DIR, 'model.joblib')
SCALER_PATH = os.path.join(TOOLKIT_DIR, 'scaler.joblib')
ANOMALY_MODEL_PATH = os.path.join(TOOLKIT_DIR, 'anomaly_model.joblib')

PROCESS_SEVERITY_DB = {
    'nc.exe': (10, 'CRITICAL: Netcat - Remote access tool'),
    'nc64.exe': (10, 'CRITICAL: Netcat 64-bit - Remote access tool'),
    'mimikatz.exe': (10, 'CRITICAL: Credential dumping tool'),
    'psexec.exe': (9, 'CRITICAL: Remote execution tool'),
    'procdump.exe': (8, 'HIGH: Memory dumping tool'),
    'certutil.exe': (7, 'HIGH: Often abused for downloading malware'),
    
    # High risk
    'powershell.exe': (6, 'HIGH: PowerShell - Monitor for suspicious scripts'),
    'cmd.exe': (5, 'MEDIUM: Command prompt - Check parent process'),
    'wscript.exe': (6, 'HIGH: Windows Script Host - Common malware vector'),
    'cscript.exe': (6, 'HIGH: Command-line script host'),
    'mshta.exe': (7, 'HIGH: HTML Application host - Often exploited'),
    'regsvr32.exe': (6, 'HIGH: Can execute scripts via COM objects'),
    'rundll32.exe': (6, 'HIGH: DLL execution - Often abused'),
    'bitsadmin.exe': (5, 'MEDIUM: File transfer utility'),
    
    # System processes (suspicious if wrong context)
    'svchost.exe': (4, 'MEDIUM: System service host - Verify legitimacy'),
    'lsass.exe': (3, 'INFO: Authentication process - Must run as SYSTEM'),
    'csrss.exe': (3, 'INFO: Client/Server Runtime - Must be in System32'),
    'winlogon.exe': (3, 'INFO: Windows Logon - Verify location'),
    'services.exe': (3, 'INFO: Service Control Manager'),
    'smss.exe': (3, 'INFO: Session Manager Subsystem'),
    
    # Browsers (low risk unless anomalous)
    'chrome.exe': (1, 'LOW: Google Chrome browser'),
    'firefox.exe': (1, 'LOW: Mozilla Firefox browser'),
    'msedge.exe': (1, 'LOW: Microsoft Edge browser'),
    'iexplore.exe': (2, 'LOW: Internet Explorer - Outdated browser'),
    
    # Common applications
    'explorer.exe': (1, 'LOW: Windows Explorer'),
    'notepad.exe': (0, 'BENIGN: Text editor'),
    'calc.exe': (0, 'BENIGN: Calculator'),
}

LEGITIMATE_PATHS = {
    'svchost.exe': [r'C:\Windows\System32', r'C:\Windows\SysWOW64'],
    'lsass.exe': [r'C:\Windows\System32'],
    'csrss.exe': [r'C:\Windows\System32'],
    'services.exe': [r'C:\Windows\System32'],
}


class DatasetManager:
    DATASETS = {
        'ember': {
            'name': 'EMBER Dataset',
            'url': 'https://github.com/elastic/ember/raw/master/ember/ember_dataset_2018_2.tar.bz2',
            'size': '~300MB',
            'type': 'malware_pe',
            'features': ['pe_features', 'strings', 'imports', 'exports']
        },
        'synthetic': {
            'name': 'Synthetic Process Dataset',
            'size': '~5MB',
            'type': 'process_behavior',
            'features': ['cpu', 'memory', 'connections', 'behavior']
        }
    }
    
    def __init__(self, datasets_dir):
        self.datasets_dir = Path(datasets_dir)
        self.datasets_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_synthetic_dataset(self, n_samples=50000):
        print(f"Generating synthetic dataset with {n_samples} samples...")
        
        np.random.seed(42)
        
        data = []
        
        # Benign processes (70%)
        n_benign = int(n_samples * 0.7)
        for _ in range(n_benign):
            sample = {
                'cpu_percent': np.random.exponential(2),
                'memory_percent': np.random.exponential(3),
                'conn_count': np.random.poisson(1),
                'thread_count': np.random.poisson(5) + 1,
                'handles': np.random.normal(100, 50),
                'read_bytes': np.random.exponential(10000),
                'write_bytes': np.random.exponential(5000),
                'name_length': np.random.randint(5, 20),
                'has_window': np.random.choice([0, 1], p=[0.3, 0.7]),
                'parent_exists': 1,
                'path_in_system32': np.random.choice([0, 1], p=[0.5, 0.5]),
                'known_malicious_name': 0,
                'high_cpu_memory': 0,
                'label': 0
            }
            data.append(sample)
        
        # Suspicious processes (20%)
        n_suspicious = int(n_samples * 0.2)
        for _ in range(n_suspicious):
            sample = {
                'cpu_percent': np.random.uniform(10, 40),
                'memory_percent': np.random.uniform(5, 20),
                'conn_count': np.random.poisson(3),
                'thread_count': np.random.poisson(10) + 1,
                'handles': np.random.normal(200, 80),
                'read_bytes': np.random.exponential(50000),
                'write_bytes': np.random.exponential(30000),
                'name_length': np.random.randint(8, 30),
                'has_window': np.random.choice([0, 1], p=[0.7, 0.3]),
                'parent_exists': np.random.choice([0, 1], p=[0.3, 0.7]),
                'path_in_system32': 0,
                'known_malicious_name': np.random.choice([0, 1], p=[0.7, 0.3]),
                'high_cpu_memory': 1,
                'label': 1
            }
            data.append(sample)
        
        # Malicious processes (10%)
        n_malicious = n_samples - n_benign - n_suspicious
        for _ in range(n_malicious):
            sample = {
                'cpu_percent': np.random.uniform(20, 80),
                'memory_percent': np.random.uniform(10, 50),
                'conn_count': np.random.poisson(5) + 2,
                'thread_count': np.random.poisson(15) + 5,
                'handles': np.random.normal(300, 100),
                'read_bytes': np.random.exponential(100000),
                'write_bytes': np.random.exponential(80000),
                'name_length': np.random.randint(10, 40),
                'has_window': 0,
                'parent_exists': np.random.choice([0, 1], p=[0.6, 0.4]),
                'path_in_system32': 0,
                'known_malicious_name': 1,
                'high_cpu_memory': 1,
                'label': 2 
            }
            data.append(sample)
        
        df = pd.DataFrame(data)
        
        # Shuffle
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Save
        output_path = self.datasets_dir / 'synthetic_process_dataset.csv'
        df.to_csv(output_path, index=False)
        print(f"Synthetic dataset saved to: {output_path}")
        
        return output_path
    
    def load_dataset(self, name='synthetic'):
       
        if name == 'synthetic':
            dataset_path = self.datasets_dir / 'synthetic_process_dataset.csv'
            if not dataset_path.exists():
                dataset_path = self.generate_synthetic_dataset()
            
            df = pd.read_csv(dataset_path)
            return df
        
        return None


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def ensure_reports_folder():
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    reports_base = os.path.join(BASE_DIR, 'Reports')
    os.makedirs(reports_base, exist_ok=True)
    folder = os.path.join(reports_base, f"report_{socket.gethostname()}_{timestamp}")
    os.makedirs(folder, exist_ok=True)
    return folder

def get_cpu_info():
    info = {}
    try:
        info['physical_cores'] = psutil.cpu_count(logical=False)
        info['logical_cpus'] = psutil.cpu_count(logical=True)
    except Exception:
        info['physical_cores'] = 'Unknown'
        info['logical_cpus'] = 'Unknown'

    try:
        freq = psutil.cpu_freq()
        if freq:
            info['max_freq_mhz'] = round(freq.max, 2) if freq.max else 'Unknown'
            info['current_freq_mhz'] = round(freq.current, 2) if freq.current else 'Unknown'
        else:
            info['max_freq_mhz'] = 'Unknown'
            info['current_freq_mhz'] = 'Unknown'
    except Exception:
        info['max_freq_mhz'] = 'Unknown'
        info['current_freq_mhz'] = 'Unknown'

    try:
        per_core = psutil.cpu_percent(interval=0.5, percpu=True)
        info['per_core_percent'] = per_core
    except Exception:
        info['per_core_percent'] = []

    info['cache_size'] = 'Unknown'
    try:
        if CPUINFO_AVAILABLE:
            ci = cpuinfo.get_cpu_info()
            cache = ci.get('l2_cache_size') or ci.get('l3_cache_size')
            if cache:
                info['cache_size'] = cache
    except Exception:
        pass

    return info


def is_process_suspicious(proc_info):
    suspicion_reasons = []
    
    name = proc_info.get('name', '').lower()
    path = proc_info.get('exe_path', '').lower()
    
    # Check if process is in wrong location
    if name in LEGITIMATE_PATHS:
        legitimate = any(legit_path.lower() in path for legit_path in LEGITIMATE_PATHS[name])
        if not legitimate and path:
            suspicion_reasons.append(f"Process running from unusual location: {path}")
    
    # Check for high resource usage
    if proc_info.get('cpu_percent', 0) > 50:
        suspicion_reasons.append(f"High CPU usage: {proc_info['cpu_percent']:.1f}%")
    
    if proc_info.get('memory_percent', 0) > 30:
        suspicion_reasons.append(f"High memory usage: {proc_info['memory_percent']:.1f}%")
    
    # Check for many connections
    if proc_info.get('conn_count', 0) > 10:
        suspicion_reasons.append(f"Many network connections: {proc_info['conn_count']}")
    
    # Check if system process running as user
    system_procs = ['svchost.exe', 'lsass.exe', 'csrss.exe', 'services.exe']
    username = proc_info.get('username', '').lower()
    if name in system_procs and 'system' not in username and 'service' not in username:
        suspicion_reasons.append(f"System process running as user: {username}")
    
    # Check for no parent process (except for system init processes)
    if not proc_info.get('parent_exists') and name not in ['system', 'smss.exe', 'wininit.exe']:
        suspicion_reasons.append("No parent process found")
    
    return suspicion_reasons

def extract_features_for_ml(proc_info):
    name = proc_info.get('name', 'unknown').lower()
    username = proc_info.get('username', '').lower()
    
    features = {
        'cpu_percent': float(proc_info.get('cpu_percent', 0.0)),
        'memory_percent': float(proc_info.get('memory_percent', 0.0)),
        'conn_count': int(proc_info.get('conn_count', 0)),
        'thread_count': int(proc_info.get('thread_count', 0)),
        'handles': int(proc_info.get('handles', 0)),
        'read_bytes': float(proc_info.get('read_bytes', 0)),
        'write_bytes': float(proc_info.get('write_bytes', 0)),
        'name_length': len(name),
        'has_window': int(proc_info.get('has_window', False)),
        'parent_exists': int(proc_info.get('parent_exists', True)),
        'path_in_system32': int('system32' in proc_info.get('exe_path', '').lower()),
        'known_malicious_name': int(name in PROCESS_SEVERITY_DB and PROCESS_SEVERITY_DB[name][0] >= 7),
        'high_cpu_memory': int(proc_info.get('cpu_percent', 0) > 30 or proc_info.get('memory_percent', 0) > 20),
    }
    
    return features

def analyze_process(proc):
    p_info = {
        'pid': getattr(proc, 'pid', 'N/A'),
        'name': 'N/A',
        'username': 'N/A',
        'status': 'N/A',
        'exe_path': 'N/A',
        'cmdline': 'N/A',
        'classification': 'Unknown',
        'severity_score': 0,
        'reason': 'Benign process',
        'cpu_percent': 0.0,
        'memory_percent': 0.0,
        'conn_count': 0,
        'thread_count': 0,
        'handles': 0,
        'read_bytes': 0,
        'write_bytes': 0,
        'create_time': 'N/A',
        'parent_pid': 'N/A',
        'parent_exists': False,
        'has_window': False,
    }
    
    try:
        p_info['name'] = proc.name()
        
        try:
            p_info['username'] = proc.username()
        except:
            pass
        
        try:
            p_info['status'] = proc.status()
        except:
            pass
        
        try:
            p_info['exe_path'] = proc.exe()
        except:
            pass
        
        try:
            cmdline = proc.cmdline()
            p_info['cmdline'] = ' '.join(cmdline) if cmdline else 'N/A'
        except:
            pass
        
        try:
            p_info['cpu_percent'] = proc.cpu_percent(interval=0.0)
        except:
            pass
        
        try:
            mem_info = proc.memory_info()
            p_info['memory_percent'] = proc.memory_percent()
        except:
            pass
        
        try:
            conns = proc.net_connections(kind='inet')
            p_info['conn_count'] = len(conns)
        except:
            pass
        
        try:
            p_info['thread_count'] = proc.num_threads()
        except:
            pass
        
        try:
            p_info['handles'] = proc.num_handles() if hasattr(proc, 'num_handles') else 0
        except:
            pass
        
        try:
            io_counters = proc.io_counters()
            p_info['read_bytes'] = io_counters.read_bytes
            p_info['write_bytes'] = io_counters.write_bytes
        except:
            pass
        
        try:
            p_info['create_time'] = datetime.datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')
        except:
            pass
        
        try:
            ppid = proc.ppid()
            p_info['parent_pid'] = ppid
            if ppid:
                try:
                    psutil.Process(ppid)
                    p_info['parent_exists'] = True
                except:
                    p_info['parent_exists'] = False
        except:
            pass
        
        # Classification
        if p_info['username'] and 'system' in str(p_info['username']).lower():
            p_info['classification'] = 'System Process'
        elif p_info['conn_count'] > 0:
            p_info['classification'] = 'Networked Application'
        else:
            p_info['classification'] = 'User Application'

        # Base severity from DB
        proc_name_lower = p_info['name'].lower()
        if proc_name_lower in PROCESS_SEVERITY_DB:
            score, reason = PROCESS_SEVERITY_DB[proc_name_lower]
            p_info['severity_score'] = score
            p_info['reason'] = reason
        
        # Add suspicion reasons
        suspicion_reasons = is_process_suspicious(p_info)
        if suspicion_reasons:
            p_info['severity_score'] = max(p_info['severity_score'], 5)
            p_info['suspicion_reasons'] = suspicion_reasons
        else:
            p_info['suspicion_reasons'] = []

    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        p_info['status'] = 'Access Denied or Terminated'
        p_info['severity_score'] = 3
        p_info['reason'] = 'Could not access process details'
    except Exception as e:
        p_info['status'] = f'Error: {str(e)[:50]}'

    return p_info

def group_processes(processes):
    grouped = defaultdict(lambda: {
        'pids': [],
        'count': 0,
        'total_cpu': 0.0,
        'total_memory': 0.0,
        'total_connections': 0,
        'max_severity': 0,
        'reasons': set(),
        'suspicion_reasons': [],
        'usernames': set(),
        'ml_predictions': []
    })
    
    for proc in processes:
        name = proc['name']
        group = grouped[name]
        
        group['pids'].append(str(proc['pid']))
        group['count'] += 1
        group['total_cpu'] += proc.get('cpu_percent', 0)
        group['total_memory'] += proc.get('memory_percent', 0)
        group['total_connections'] += proc.get('conn_count', 0)
        group['max_severity'] = max(group['max_severity'], proc.get('severity_score', 0))
        
        if proc.get('reason'):
            group['reasons'].add(proc['reason'])
        
        if proc.get('suspicion_reasons'):
            group['suspicion_reasons'].extend(proc['suspicion_reasons'])
        
        if proc.get('username') != 'N/A':
            group['usernames'].add(proc['username'])
        
        if proc.get('ml_prediction') is not None:
            group['ml_predictions'].append(proc['ml_prediction'])
    
    # Convert to list format
    result = []
    for name, data in grouped.items():
        result.append({
            'name': name,
            'pids': ', '.join(data['pids']),
            'count': data['count'],
            'avg_cpu': data['total_cpu'] / data['count'] if data['count'] > 0 else 0,
            'avg_memory': data['total_memory'] / data['count'] if data['count'] > 0 else 0,
            'total_connections': data['total_connections'],
            'severity_score': data['max_severity'],
            'reason': '; '.join(data['reasons']) if data['reasons'] else 'N/A',
            'suspicion_reasons': list(set(data['suspicion_reasons']))[:3],  # Top 3 unique reasons
            'usernames': ', '.join(data['usernames']) if data['usernames'] else 'N/A',
            'ml_prediction': max(data['ml_predictions']) if data['ml_predictions'] else None,
        })
    
    return sorted(result, key=lambda x: x['severity_score'], reverse=True)


def get_network_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED':
            try:
                local = f"{conn.laddr.ip}:{conn.laddr.port}"
            except:
                local = 'N/A'
            try:
                remote = f"{conn.raddr.ip}:{conn.raddr.port}"
            except:
                remote = 'N/A'
            
            conn_info = {
                'pid': conn.pid or 'N/A',
                'process_name': 'N/A',
                'local_addr': local,
                'remote_addr': remote,
                'status': conn.status
            }
            
            try:
                if conn.pid:
                    conn_info['process_name'] = psutil.Process(conn.pid).name()
            except:
                pass
            
            connections.append(conn_info)
    
    return connections


def create_process_chart(processes):
    classifications = {}
    for proc in processes:
        cat = proc['classification']
        classifications[cat] = classifications.get(cat, 0) + 1

    if not classifications:
        return None

    labels = list(classifications.keys())
    sizes = list(classifications.values())
    colors = ['#4CAF50', '#2196F3', '#FF9800', '#F44336']

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors[:len(labels)])
    ax.axis('equal')
    plt.title('Process Classification Distribution')

    buf = BytesIO()
    plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
    buf.seek(0)
    image_base64 = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()
    plt.close(fig)

    return f"data:image/png;base64,{image_base64}"

def create_severity_chart(grouped_processes):
    severity_counts = {'Low (0-3)': 0, 'Medium (4-6)': 0, 'High (7-8)': 0, 'Critical (9-10)': 0}
    
    for proc in grouped_processes:
        score = proc['severity_score']
        if score <= 3:
            severity_counts['Low (0-3)'] += proc['count']
        elif score <= 6:
            severity_counts['Medium (4-6)'] += proc['count']
        elif score <= 8:
            severity_counts['High (7-8)'] += proc['count']
        else:
            severity_counts['Critical (9-10)'] += proc['count']
    
    labels = list(severity_counts.keys())
    sizes = list(severity_counts.values())
    colors = ['#4CAF50', '#FF9800', '#FF5722', '#9C27B0']
    
    fig, ax = plt.subplots(figsize=(8, 6))
    bars = ax.bar(labels, sizes, color=colors)
    ax.set_ylabel('Number of Processes')
    ax.set_title('Process Severity Distribution')
    plt.xticks(rotation=15)
    
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom')
    
    buf = BytesIO()
    plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
    buf.seek(0)
    image_base64 = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()
    plt.close(fig)
    
    return f"data:image/png;base64,{image_base64}"


def train_ml_model(dataset_manager):
    if not SKLEARN_AVAILABLE:
        print("Scikit-learn not available. Skipping ML training.")
        return None, None
    
    print("Loading dataset...")
    df = dataset_manager.load_dataset('synthetic')
    
    if df is None:
        print("Failed to load dataset")
        return None, None
    
    print(f"Dataset loaded: {len(df)} samples")
    
    # Prepare features and labels
    feature_columns = ['cpu_percent', 'memory_percent', 'conn_count', 'thread_count',
                      'handles', 'read_bytes', 'write_bytes', 'name_length',
                      'has_window', 'parent_exists', 'path_in_system32',
                      'known_malicious_name', 'high_cpu_memory']
    
    X = df[feature_columns].values
    y = df['label'].values
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train classifier
    print("Training RandomForest classifier...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
    clf.fit(X_train_scaled, y_train)
    
    # Evaluate
    train_score = clf.score(X_train_scaled, y_train)
    test_score = clf.score(X_test_scaled, y_test)
    print(f"Training accuracy: {train_score:.3f}")
    print(f"Testing accuracy: {test_score:.3f}")

    print("\nEvaluating classifier on the test set...")
    y_pred = clf.predict(X_test_scaled)
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print("\nClassification Report:")
    report = classification_report(y_test, y_pred)
    print(report)
    
    # Train anomaly detector
    print("Training Isolation Forest for anomaly detection...")
    anomaly_clf = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
    anomaly_clf.fit(X_train_scaled)
    anomaly_scores = anomaly_clf.score_samples(X_train_scaled) 
    average_anomaly_score = anomaly_scores.mean()
    print(f"Average anomaly score on train set: {average_anomaly_score:.3f}")
    anomaly_scores = anomaly_clf.score_samples(X_test_scaled) 
    average_anomaly_score = anomaly_scores.mean()
    print(f"Average anomaly score on test set: {average_anomaly_score:.3f}")
    

    
    # Save models
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(anomaly_clf, ANOMALY_MODEL_PATH)
    print(f"Models saved to {TOOLKIT_DIR}")
    
    return clf, scaler, anomaly_clf

def load_ml_models():
    if not SKLEARN_AVAILABLE:
        return None, None, None
    
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            clf = joblib.load(MODEL_PATH)
            scaler = joblib.load(SCALER_PATH)
            anomaly_clf = None
            if os.path.exists(ANOMALY_MODEL_PATH):
                anomaly_clf = joblib.load(ANOMALY_MODEL_PATH)
            print("ML models loaded successfully")
            return clf, scaler, anomaly_clf
    except Exception as e:
        print(f"Error loading models: {e}")
    
    return None, None, None

def predict_process_threat(proc_info, clf, scaler, anomaly_clf):
    if clf is None or scaler is None:
        return None, None, None
    
    features = extract_features_for_ml(proc_info)
    feature_vector = np.array([[
        features['cpu_percent'],
        features['memory_percent'],
        features['conn_count'],
        features['thread_count'],
        features['handles'],
        features['read_bytes'],
        features['write_bytes'],
        features['name_length'],
        features['has_window'],
        features['parent_exists'],
        features['path_in_system32'],
        features['known_malicious_name'],
        features['high_cpu_memory']
    ]])
    
    # Scale features
    feature_vector_scaled = scaler.transform(feature_vector)
    
    # Predict
    prediction = clf.predict(feature_vector_scaled)[0]
    prediction_proba = clf.predict_proba(feature_vector_scaled)[0]
    
    # Anomaly detection
    anomaly_score = None
    if anomaly_clf is not None:
        anomaly_pred = anomaly_clf.predict(feature_vector_scaled)[0]
        anomaly_score = anomaly_clf.score_samples(feature_vector_scaled)[0]
        if anomaly_pred == -1:  # Anomaly detected
            prediction = max(prediction, 1)  # Upgrade to at least suspicious
    
    return int(prediction), prediction_proba.tolist(), anomaly_score


def generate_html_report(report_data):
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Forensic Triage Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                color: #333;
            }}
            h1 {{
                color: #2c3e50;
                border-bottom: 3px solid #3498db;
                padding-bottom: 10px;
            }}
            h2 {{
                color: #34495e;
                border-bottom: 2px solid #95a5a6;
                padding-bottom: 5px;
                margin-top: 30px;
            }}
            .header {{
                background: #ecf0f1;
                padding: 15px;
                border-radius: 5px;
                margin-bottom: 20px;
            }}
            .threat-critical {{
                background: #e74c3c;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }}
            .threat-high {{
                background: #e67e22;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }}
            .threat-medium {{
                background: #f39c12;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }}
            .threat-low {{
                background: #27ae60;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
                font-size: 11px;
            }}
            th {{
                background: #34495e;
                color: white;
                padding: 8px;
                text-align: left;
                font-weight: bold;
            }}
            td {{
                padding: 6px;
                border-bottom: 1px solid #ddd;
            }}
            tr:hover {{
                background: #f5f5f5;
            }}
            .severity-10 {{ background: #8e44ad; color: white; }}
            .severity-9 {{ background: #c0392b; color: white; }}
            .severity-8 {{ background: #e74c3c; color: white; }}
            .severity-7 {{ background: #d35400; color: white; }}
            .severity-6 {{ background: #e67e22; }}
            .severity-5 {{ background: #f39c12; }}
            .severity-4 {{ background: #f1c40f; }}
            .info-box {{
                background: #d5f4e6;
                border-left: 4px solid #27ae60;
                padding: 10px;
                margin: 10px 0;
            }}
            .warning-box {{
                background: #ffeaa7;
                border-left: 4px solid #f39c12;
                padding: 10px;
                margin: 10px 0;
            }}
            .chart {{
                text-align: center;
                margin: 20px 0;
            }}
            .chart img {{
                max-width: 600px;
                height: auto;
            }}
            ul {{
                margin: 5px 0;
                padding-left: 20px;
            }}
        </style>
    </head>
    <body>
        <h1>Forensic Triage Report - {report_data['system_info']['hostname']}</h1>
        
        <div class="header">
            <strong>Report Time:</strong> {report_data['system_info']['report_time']}<br>
            <strong>Analyzed By:</strong> Enhanced Forensic Triage System v2.0
        </div>
        
        <h2>System Information</h2>
        <table>
            <tr>
                <th>Property</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Operating System</td>
                <td>{report_data['system_info']['os']}</td>
            </tr>
            <tr>
                <td>User</td>
                <td>{report_data['system_info']['user']}</td>
            </tr>
            <tr>
                <td>CPU Physical Cores</td>
                <td>{report_data['system_info']['cpu']['physical_cores']}</td>
            </tr>
            <tr>
                <td>CPU Logical Cores</td>
                <td>{report_data['system_info']['cpu']['logical_cpus']}</td>
            </tr>
            <tr>
                <td>CPU Max Frequency</td>
                <td>{report_data['system_info']['cpu']['max_freq_mhz']} MHz</td>
            </tr>
            <tr>
                <td>CPU Cache Size</td>
                <td>{report_data['system_info']['cpu']['cache_size']}</td>
            </tr>
        </table>
        
        <h2>Threat Assessment</h2>
        <div class="threat-{report_data['threat_level'].lower()}">
            Threat Level: {report_data['threat_level']} (Score: {report_data['threat_score']})
        </div>
        
        <div class="info-box">
            <strong>Summary:</strong> {report_data['summary_text']}
        </div>
        
        <h2>Process Analysis</h2>
        <p><strong>Total Processes:</strong> {report_data['total_processes']} | 
           <strong>Unique Process Names:</strong> {len(report_data['grouped_processes'])} |
           <strong>High-Risk Processes:</strong> {report_data['high_risk_count']}</p>
        
        <h3>Grouped Processes (Top 20 by Severity)</h3>
        <table>
            <tr>
                <th>Process Name</th>
                <th>PIDs (Count)</th>
                <th>Avg CPU%</th>
                <th>Avg Mem%</th>
                <th>Conns</th>
                <th>Severity</th>
                <th>ML</th>
                <th>Reason / Issues</th>
            </tr>
    """
    
    for proc in report_data['grouped_processes'][:]:
        severity_class = f"severity-{proc['severity_score']}" if proc['severity_score'] >= 4 else ""
        ml_pred = proc.get('ml_prediction', 'N/A')
        ml_text = {0: 'Benign', 1: 'Suspicious', 2: 'Malicious'}.get(ml_pred, 'N/A')
        
        suspicion_list = ""
        if proc.get('suspicion_reasons'):
            suspicion_list = "<ul>" + "".join([f"<li>{r}</li>" for r in proc['suspicion_reasons'][:3]]) + "</ul>"
        
        html += f"""
            <tr class="{severity_class}">
                <td><strong>{proc['name']}</strong></td>
                <td>{proc['pids'][:50]}{'...' if len(proc['pids']) > 50 else ''} ({proc['count']})</td>
                <td>{proc['avg_cpu']:.1f}%</td>
                <td>{proc['avg_memory']:.1f}%</td>
                <td>{proc['total_connections']}</td>
                <td>{proc['severity_score']}</td>
                <td>{ml_text}</td>
                <td>{proc['reason']}{suspicion_list}</td>
            </tr>
        """
    
    html += """
        </table>
        
        <h2>Visualizations</h2>
    """
    
    if report_data.get('classification_chart'):
        html += f"""
        <div class="chart">
            <h3>Process Classification Distribution</h3>
            <img src="{report_data['classification_chart']}" alt="Classification Chart">
        </div>
        """
    
    if report_data.get('severity_chart'):
        html += f"""
        <div class="chart">
            <h3>Severity Distribution</h3>
            <img src="{report_data['severity_chart']}" alt="Severity Chart">
        </div>
        """
    
    html += f"""
        <h2>Network Connections</h2>
        <p><strong>Active Established Connections:</strong> {len(report_data['network_connections'])}</p>
        <table>
            <tr>
                <th>PID</th>
                <th>Process Name</th>
                <th>Local Address</th>
                <th>Remote Address</th>
            </tr>
    """
    
    for conn in report_data['network_connections'][:30]:
        html += f"""
            <tr>
                <td>{conn['pid']}</td>
                <td>{conn['process_name']}</td>
                <td>{conn['local_addr']}</td>
                <td>{conn['remote_addr']}</td>
            </tr>
        """
    
    if len(report_data['network_connections']) > 30:
        html += f"<tr><td colspan='4'><em>... and {len(report_data['network_connections']) - 30} more connections</em></td></tr>"
    
    html += """
        </table>
        
        <h2>Recommendations</h2>
        <div class="warning-box">
    """
    
    for rec in report_data.get('recommendations', []):
        html += f"<p>• {rec}</p>"
    
    html += """
        </div>
        
        <div class="info-box">
            <small><strong>Note:</strong> This report is for forensic analysis purposes. 
            Verify all findings manually before taking action. ML predictions are probabilistic 
            and should be used as additional indicators, not sole decision criteria.</small>
        </div>
    </body>
    </html>
    """
    
    return html

def generate_pdf_report(report_data, html_string, out_folder):
    hostname = report_data.get('system_info', {}).get('hostname', 'UnknownPC')
    safe_name = ''.join(c for c in hostname if c.isalnum() or c in ('-', '_'))
    pdf_filename = os.path.join(out_folder, f"Triage-Report-{safe_name}.pdf")
    
    try:
        with open(pdf_filename, 'wb') as pdf_file:
            pisa_status = pisa.CreatePDF(html_string, dest=pdf_file)
        
        if pisa_status.err:
            print("PDF generation had errors")
            return None
        
        print(f"PDF generated: {pdf_filename}")
        return pdf_filename
    except Exception as e:
        print(f"PDF creation failed: {e}")
        return None


def send_email_with_attachment(subject, body, to_email, attachment_path):
    if not SMTP_SENDER or not SMTP_APP_PASSWORD:
        print('Email credentials not configured. Skipping email.')
        return
    
    msg = MIMEMultipart()
    msg['From'] = SMTP_SENDER
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    if attachment_path and os.path.exists(attachment_path):
        with open(attachment_path, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(attachment_path)}')
        msg.attach(part)
    
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(SMTP_SENDER, SMTP_APP_PASSWORD)
            smtp_server.send_message(msg)
        print('Email sent successfully')
    except Exception as e:
        print(f'Failed to send email: {e}')

# --------------------------- MAIN ORCHESTRATION ---------------------------

def generate_recommendations(report_data):
    recommendations = []
    
    if report_data['threat_score'] >= 70:
        recommendations.append("🔴 CRITICAL: Immediate investigation required. Multiple high-severity processes detected.")
        recommendations.append("Disconnect the system from the network if possible.")
    elif report_data['threat_score'] >= 40:
        recommendations.append("🟠 HIGH PRIORITY: Review all flagged processes immediately.")
    
    # Check for specific threats
    high_risk_procs = [p for p in report_data['grouped_processes'] if p['severity_score'] >= 7]
    if high_risk_procs:
        recommendations.append(f"Found {len(high_risk_procs)} high-risk process types. Investigate: {', '.join([p['name'] for p in high_risk_procs[:5]])}")
    
    # Check for unusual network activity
    if len(report_data['network_connections']) > 50:
        recommendations.append(f"High number of network connections detected ({len(report_data['network_connections'])}). Review for unauthorized communications.")
    
    # ML-based recommendations
    ml_suspicious = [p for p in report_data['grouped_processes'] if p.get('ml_prediction', 0) >= 1]
    if ml_suspicious:
        recommendations.append(f"ML model flagged {len(ml_suspicious)} process types as suspicious or malicious.")
    
    # Check for processes without parents
    orphan_procs = [p for p in report_data['grouped_processes'] if any('No parent' in str(s) for s in p.get('suspicion_reasons', []))]
    if orphan_procs:
        recommendations.append(f"Found {len(orphan_procs)} orphaned processes (no parent). May indicate process injection.")
    
    if not recommendations:
        recommendations.append("✅ No immediate threats detected. System appears normal.")
        recommendations.append("Continue monitoring for unusual behavior.")
    
    recommendations.append("Regularly update antivirus definitions and run full system scans.")
    recommendations.append("Review Windows Event Logs for correlated suspicious activity.")
    
    return recommendations

def main(ml_mode=True, download_dataset=None, train_model=False, email_report=None):
    print("=" * 60)
    print("Enhanced Forensic Triage System v2.0")
    print("=" * 60)
    
    # Handle dataset download
    if download_dataset:
        dataset_manager = DatasetManager(DATASETS_DIR)
        if download_dataset == 'synthetic':
            dataset_manager.generate_synthetic_dataset(n_samples=10000)
        print("Dataset ready. Run again with --ml-mode on to train model.")
        return
    if train_model:
        dataset_manager = DatasetManager(DATASETS_DIR)
        train_ml_model(dataset_manager)
        print("Model training complete. Run again with --ml-mode on to use the model.")
        return
    
    
    print(f"ML Mode: {'Enabled' if ml_mode else 'Disabled'}")
    out_folder = ensure_reports_folder()
    print(f"Output folder: {out_folder}")
    
    # System info
    print("\nGathering system information...")
    uname = platform.uname()
    system_info = {
        'hostname': socket.gethostname(),
        'report_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'user': getpass.getuser(),
        'os': f"{uname.system} {uname.release}",
        'cpu': get_cpu_info(),
    }
    
    # ML model handling
    clf, scaler, anomaly_clf = None, None, None
    if ml_mode and SKLEARN_AVAILABLE:
        print("\nLoading/training ML models...")
        clf, scaler, anomaly_clf = load_ml_models()
        
        if clf is None:
            print("No trained model found. Training new model...")
            dataset_manager = DatasetManager(DATASETS_DIR)
            clf, scaler, anomaly_clf = train_ml_model(dataset_manager)
    
    # Gather processes
    print("\nAnalyzing processes...")
    processes = []
    for p in psutil.process_iter(attrs=[], ad_value=None):
        proc_info = analyze_process(p)
        
        # Add ML prediction
        if clf is not None:
            ml_pred, ml_proba, anomaly_score = predict_process_threat(proc_info, clf, scaler, anomaly_clf)
            proc_info['ml_prediction'] = ml_pred
            proc_info['ml_probability'] = ml_proba
            proc_info['anomaly_score'] = anomaly_score
            
            # Adjust severity based on ML
            if ml_pred == 2:  # Malicious
                proc_info['severity_score'] = max(proc_info['severity_score'], 8)
            elif ml_pred == 1:  # Suspicious
                proc_info['severity_score'] = max(proc_info['severity_score'], 5)
        
        processes.append(proc_info)
    
    print(f"Analyzed {len(processes)} processes")
    
    # Group processes
    print("Grouping processes by name...")
    grouped_processes = group_processes(processes)
    
    # Network connections
    print("Analyzing network connections...")
    net_conns = get_network_connections()
    
    # Calculate threat score
    threat_score = sum(p['severity_score'] for p in processes)
    high_risk_count = sum(1 for p in processes if p['severity_score'] >= 7)
    
    if threat_score == 0:
        threat_level = 'Clean'
    elif threat_score <= 15:
        threat_level = 'Low'
    elif threat_score <= 40:
        threat_level = 'Medium'
    elif threat_score <= 70:
        threat_level = 'High'
    else:
        threat_level = 'Critical'
    
    # Create visualizations
    print("Generating visualizations...")
    classification_chart = create_process_chart(processes)
    severity_chart = create_severity_chart(grouped_processes)
    
    # Prepare report data
    report_data = {
        'system_info': system_info,
        'threat_score': threat_score,
        'threat_level': threat_level,
        'total_processes': len(processes),
        'high_risk_count': high_risk_count,
        'summary_text': f"Analyzed {len(processes)} processes ({len(grouped_processes)} unique). Found {high_risk_count} high-severity processes and {len(net_conns)} active network connections.",
        'classification_chart': classification_chart,
        'severity_chart': severity_chart,
        'grouped_processes': grouped_processes,
        'network_connections': net_conns,
        'ml_enabled': ml_mode and clf is not None,
    }
    
    # Generate recommendations
    report_data['recommendations'] = generate_recommendations(report_data)
    
    # Save JSON report
    print("\nSaving JSON report...")
    json_path = os.path.join(out_folder, 'report.json')
    with open(json_path, 'w') as jf:
        json.dump(report_data, jf, indent=2, default=str)
    
    json_hash = sha256_of_file(json_path)
    with open(os.path.join(out_folder, 'report.json.sha256'), 'w') as hf:
        hf.write(json_hash)
    
    # Generate HTML and PDF
    print("Generating HTML report...")
    html_output = generate_html_report(report_data)
    
    html_path = os.path.join(out_folder, 'report.html')
    with open(html_path, 'w', encoding='utf-8') as hf:
        hf.write(html_output)
    
    print("Generating PDF report...")
    pdf_path = generate_pdf_report(report_data, html_output, out_folder)
    
    if pdf_path:
        pdf_hash = sha256_of_file(pdf_path)
        with open(os.path.join(out_folder, 'report.pdf.sha256'), 'w') as ph:
            ph.write(pdf_hash)
    
    # Print summary
    print("\n" + "=" * 60)
    print("TRIAGE COMPLETE")
    print("=" * 60)
    print(f"Threat Level: {threat_level} (Score: {threat_score})")
    print(f"High-Risk Processes: {high_risk_count}")
    print(f"Network Connections: {len(net_conns)}")
    print(f"\nReports saved to: {out_folder}")
    print(f"JSON Hash: {json_hash[:16]}...")
    if pdf_path:
        print(f"PDF: {os.path.basename(pdf_path)}")
    
    # Email report
    if SMTP_SENDER and SMTP_APP_PASSWORD and SMTP_RECEIVER and pdf_path:
        print("\nSending email report...")
        subject = f"Forensic Triage - {system_info['hostname']} - {threat_level}"
        body = f"Automated triage report\n\nThreat Level: {threat_level}\nScore: {threat_score}\nHigh-Risk Processes: {high_risk_count}\n\nSee attached PDF for details."
        send_email_with_attachment(subject, body, SMTP_RECEIVER, pdf_path)
    
    print("\n✓ Analysis complete!")
    
    return report_data


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Forensic Triage System')
    parser.add_argument('--ml-mode', type=str, choices=['on', 'off'], default='on',
                       help='Enable/disable ML mode')
    parser.add_argument('--download-dataset', type=str, choices=['synthetic', 'ember'],
                       help='Download and prepare dataset')
    parser.add_argument('--train-model', action='store_true',
                       help='Train ML model using existing dataset')
    
    args = parser.parse_args()
    
    ml_mode = args.ml_mode == 'on'
    
    try:
        main(ml_mode=ml_mode, download_dataset=args.download_dataset, train_model=args.train_model)
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback
        traceback.print_exc()