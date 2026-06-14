import os
import json
import pandas as pd
from flask import Flask, render_template, jsonify

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/data')
def get_data():
    df_path = os.path.join(OUTPUT_DIR, 'drift_analysis_results.csv')
    expl_path = os.path.join(OUTPUT_DIR, 'drift_explanations.json')
    
    if not os.path.exists(df_path):
        return jsonify({"error": "Data not found"}), 404
        
    df = pd.read_csv(df_path)
    df['change_date'] = pd.to_datetime(df['change_date'])
    
    # 1. Classification
    class_counts = df['classification'].value_counts().to_dict()
    mapped_class = {
        'CRITICAL': class_counts.get('CRITICAL_DRIFT', 0),
        'HIGH': class_counts.get('HIGH_DRIFT', 0),
        'MEDIUM': class_counts.get('MEDIUM_DRIFT', 0),
        'BENIGN': class_counts.get('BENIGN', 0)
    }
    
    # 2. Monthly
    df['month_year'] = df['change_date'].dt.strftime('%b %y')
    monthly_series = df.groupby('month_year').size()
    sorted_months = sorted(monthly_series.index, key=lambda x: pd.to_datetime(x, format='%b %y'))
    monthly = {m: int(monthly_series[m]) for m in sorted_months}
    
    # 3. Domain Risk
    domain_risk = df.groupby('control_type')['risk_score'].mean().round(1).sort_values(ascending=False).to_dict()
    
    # 4. Hourly
    hourly_series = df['change_date'].dt.hour.value_counts().to_dict()
    hourly = {str(h): int(hourly_series.get(h, 0)) for h in range(24)}
    
    # 5. Operators
    ops = df.groupby('operator_name')['risk_score'].sum().sort_values(ascending=False).head(10).reset_index()
    operators = [{"name": row['operator_name'], "score": int(row['risk_score'])} for _, row in ops.iterrows()]
    
    # 6. Change Types
    ct_counts = df['change_type'].value_counts().to_dict()
    
    # 7. Compliance and Frameworks
    comp_viol = {}
    for imp in df['compliance_impact'].dropna():
        for st in imp.split(','):
            st = st.strip()
            if st:
                comp_viol[st] = comp_viol.get(st, 0) + 1
    
    sorted_comp = sorted(comp_viol.items(), key=lambda x: x[1], reverse=True)
    compliance_list = []
    for k, v in sorted_comp:
        risk = 'critical' if v > 100 else 'high' if v > 50 else 'medium'
        compliance_list.append({"std": k, "cnt": v, "risk": risk, "doms": "Multiple", "cov": "100%"})

    frameworks = {
        "NIST SP 800-53": sum(v for k,v in comp_viol.items() if "NIST" in k),
        "CIS Controls v8": sum(v for k,v in comp_viol.items() if "CIS" in k),
        "GDPR": sum(v for k,v in comp_viol.items() if "GDPR" in k),
        "PCI-DSS v4": sum(v for k,v in comp_viol.items() if "PCI" in k),
        "ISO 27001:2022": sum(v for k,v in comp_viol.items() if "ISO" in k)
    }
    
    # 8. Off Hours by Domain
    df['is_off_hours'] = df['change_date'].dt.hour.between(0, 6)
    off_hours_by_domain = df[df['is_off_hours']].groupby('control_type').size().to_dict()
    # ensure all domains exist
    for dom in domain_risk.keys():
        if dom not in off_hours_by_domain:
            off_hours_by_domain[dom] = 0
            
    # 9. Regression Rate by Domain
    regr_domain = df[df['change_type'] == 'Disable'].groupby('control_type').size()
    total_domain = df.groupby('control_type').size()
    regr_rate = ((regr_domain / total_domain) * 100).fillna(0).round(1).to_dict()
    for dom in domain_risk.keys():
        if dom not in regr_rate:
            regr_rate[dom] = 0.0

    # 10. Alerts
    alerts = []
    if os.path.exists(expl_path):
        with open(expl_path, 'r') as f:
            alerts = json.load(f)[:20]
            
    payload = {
        "classification": mapped_class,
        "monthly": monthly,
        "domainRisk": domain_risk,
        "hourly": hourly,
        "operators": operators,
        "changeTypes": ct_counts,
        "compliance": compliance_list,
        "framework": frameworks,
        "offHoursByDomain": off_hours_by_domain,
        "regressionRateByDomain": regr_rate,
        "alerts": alerts
    }
    
    return jsonify(payload)

if __name__ == '__main__':
    print(" Starting Dynamic SOC Dashboard Server on http://localhost:8080")
    app.run(host='0.0.0.0', port=8080, debug=True)
