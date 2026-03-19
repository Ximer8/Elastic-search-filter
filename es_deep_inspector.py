#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced Elasticsearch Deep Inspector
Расширенный анализ индексов, маппингов, и содержимого
"""

import json
import re
from typing import Dict, List, Optional, Set, Tuple

import requests

requests.packages.urllib3.disable_warnings()


class ElasticsearchDeepInspector:
    """Глубокий анализатор Elasticsearch"""
    
    def __init__(self, scheme: str, host: str, port: int, timeout: int = 10):
        self.scheme = scheme
        self.host = host
        self.port = port
        self.timeout = timeout
        self.base_url = f"{scheme}://{host}:{port}"
        self.headers = {"User-Agent": "es-deep-inspector/1.0", "Accept": "application/json"}
    
    def get(self, path: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Выполняет GET запрос"""
        try:
            url = self.base_url + path
            r = requests.get(url, timeout=self.timeout, headers=self.headers, 
                           params=params, verify=False, allow_redirects=True)
            if r.status_code == 200:
                return r.json()
        except:
            pass
        return None
    
    def get_indices_list(self) -> List[Dict]:
        """Получает список всех индексов с метаданными"""
        data = self.get("/_cat/indices?format=json")
        if data:
            return data
        return []
    
    def get_index_mapping(self, index_name: str) -> Optional[Dict]:
        """Получает маппинг конкретного индекса"""
        return self.get(f"/{index_name}/_mapping")
    
    def get_index_settings(self, index_name: str) -> Optional[Dict]:
        """Получает настройки индекса"""
        return self.get(f"/{index_name}/_settings")
    
    def search_index(self, index_name: str, size: int = 10, query: Optional[Dict] = None) -> Optional[Dict]:
        """Поиск в индексе"""
        if query is None:
            query = {"query": {"match_all": {}}}
        
        try:
            url = f"{self.base_url}/{index_name}/_search"
            r = requests.post(url, json=query, timeout=self.timeout, headers=self.headers, verify=False)
            if r.status_code == 200:
                return r.json()
        except:
            pass
        return None
    
    def analyze_index_for_sensitive_data(self, index_name: str, sample_size: int = 50) -> Dict:
        """
        Анализирует индекс на предмет чувствительных данных
        """
        result = {
            "index": index_name,
            "total_docs": 0,
            "fields": set(),
            "sensitive_fields": [],
            "has_email": False,
            "has_phone": False,
            "has_password": False,
            "has_token": False,
            "has_credit_card": False,
            "sample_emails": set(),
            "sample_phones": set(),
            "risk_score": 0
        }
        
        # Получаем маппинг
        mapping = self.get_index_mapping(index_name)
        if mapping:
            fields = self._extract_fields_from_mapping(mapping)
            result["fields"] = fields
            result["sensitive_fields"] = self._detect_sensitive_fields(fields)
        
        # Получаем sample документов
        search_result = self.search_index(index_name, size=sample_size)
        if search_result and "hits" in search_result:
            result["total_docs"] = search_result["hits"]["total"]["value"] if isinstance(search_result["hits"]["total"], dict) else search_result["hits"]["total"]
            
            # Анализируем документы
            for hit in search_result["hits"]["hits"]:
                source = hit.get("_source", {})
                self._analyze_document(source, result)
        
        # Подсчитываем risk score
        result["risk_score"] = self._calculate_risk_score(result)
        
        return result
    
    def _extract_fields_from_mapping(self, mapping: Dict) -> Set[str]:
        """Извлекает все поля из маппинга"""
        fields = set()
        
        def traverse(obj, prefix=""):
            if isinstance(obj, dict):
                if "properties" in obj:
                    for field, props in obj["properties"].items():
                        full_name = f"{prefix}.{field}" if prefix else field
                        fields.add(full_name)
                        traverse(props, full_name)
                else:
                    for k, v in obj.items():
                        traverse(v, prefix)
            elif isinstance(obj, list):
                for item in obj:
                    traverse(item, prefix)
        
        traverse(mapping)
        return fields
    
    def _detect_sensitive_fields(self, fields: Set[str]) -> List[str]:
        """Детектирует чувствительные поля по именам"""
        sensitive_keywords = {
            "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
            "email", "mail", "phone", "mobile", "tel", "ssn", "credit_card",
            "card_number", "cvv", "pin", "private", "confidential", "internal",
            "auth", "authorization", "bearer", "access_token", "refresh_token",
            "first_name", "last_name", "full_name", "address", "dob", "birth",
            "passport", "driver_license", "medical", "health", "diagnosis"
        }
        
        sensitive = []
        for field in fields:
            field_lower = field.lower()
            for keyword in sensitive_keywords:
                if keyword in field_lower:
                    sensitive.append(field)
                    break
        
        return sensitive
    
    def _analyze_document(self, doc: Dict, result: Dict):
        """Анализирует один документ"""
        doc_str = json.dumps(doc).lower()
        
        # Email
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, json.dumps(doc))
        if emails:
            result["has_email"] = True
            result["sample_emails"].update(emails[:5])
        
        # Phone
        phone_pattern = r'\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}'
        phones = re.findall(phone_pattern, json.dumps(doc))
        if phones:
            result["has_phone"] = True
            result["sample_phones"].update(phones[:5])
        
        # Credit Card (простая проверка)
        cc_pattern = r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
        if re.search(cc_pattern, json.dumps(doc)):
            result["has_credit_card"] = True
        
        # Passwords/tokens
        if any(k in doc_str for k in ["password", "passwd", "pwd", "secret", "token"]):
            result["has_password"] = True
        
        if any(k in doc_str for k in ["token", "bearer", "authorization", "api_key"]):
            result["has_token"] = True
    
    def _calculate_risk_score(self, result: Dict) -> int:
        """Подсчитывает risk score"""
        score = 0
        
        # Чувствительные поля
        score += len(result["sensitive_fields"]) * 5
        
        # Наличие конкретных типов данных
        if result["has_email"]:
            score += 10
        if result["has_phone"]:
            score += 10
        if result["has_password"]:
            score += 50
        if result["has_token"]:
            score += 50
        if result["has_credit_card"]:
            score += 50
        
        # Количество документов (больше = хуже)
        if result["total_docs"] > 10000:
            score += 20
        elif result["total_docs"] > 1000:
            score += 10
        elif result["total_docs"] > 100:
            score += 5
        
        return min(score, 100)  # макс 100
    
    def full_analysis(self, max_indices: int = 50) -> Dict:
        """Полный анализ всех индексов"""
        indices = self.get_indices_list()
        
        result = {
            "host": f"{self.scheme}://{self.host}:{self.port}",
            "total_indices": len(indices),
            "analyzed_indices": [],
            "critical_indices": [],
            "overall_risk": 0
        }
        
        for idx_info in indices[:max_indices]:
            index_name = idx_info.get("index", "")
            if index_name.startswith("."):  # пропускаем системные
                continue
            
            print(f"    Analyzing index: {index_name}")
            analysis = self.analyze_index_for_sensitive_data(index_name)
            result["analyzed_indices"].append(analysis)
            
            if analysis["risk_score"] >= 30:
                result["critical_indices"].append(analysis)
        
        # Общий risk score
        if result["analyzed_indices"]:
            result["overall_risk"] = sum(a["risk_score"] for a in result["analyzed_indices"]) / len(result["analyzed_indices"])
        
        return result


def format_deep_analysis_report(analysis: Dict) -> str:
    """Форматирует детальный отчет глубокого анализа"""
    lines = []
    lines.append("=" * 100)
    lines.append(f"DEEP ANALYSIS REPORT: {analysis['host']}")
    lines.append("=" * 100)
    lines.append(f"Total Indices: {analysis['total_indices']}")
    lines.append(f"Analyzed: {len(analysis['analyzed_indices'])}")
    lines.append(f"Critical: {len(analysis['critical_indices'])}")
    lines.append(f"Overall Risk Score: {analysis['overall_risk']:.1f}/100")
    lines.append("")
    
    if analysis["critical_indices"]:
        lines.append("🔴 CRITICAL INDICES:")
        lines.append("-" * 100)
        
        for idx in sorted(analysis["critical_indices"], key=lambda x: -x["risk_score"]):
            lines.append(f"\n[{idx['risk_score']}] {idx['index']} ({idx['total_docs']} documents)")
            
            if idx["sensitive_fields"]:
                lines.append(f"  Sensitive fields: {', '.join(idx['sensitive_fields'][:10])}")
            
            flags = []
            if idx["has_email"]:
                flags.append(f"📧 Emails ({len(idx['sample_emails'])} found)")
            if idx["has_phone"]:
                flags.append(f"📱 Phones ({len(idx['sample_phones'])} found)")
            if idx["has_password"]:
                flags.append("🔑 Passwords/Secrets")
            if idx["has_token"]:
                flags.append("🎫 Tokens/API Keys")
            if idx["has_credit_card"]:
                flags.append("💳 Credit Cards")
            
            if flags:
                lines.append(f"  Flags: {', '.join(flags)}")
    
    lines.append("\n" + "=" * 100)
    
    return "\n".join(lines)


if __name__ == "__main__":
    # Пример использования
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python es_deep_inspector.py <scheme> <host> <port>")
        print("Example: python es_deep_inspector.py http 192.168.1.100 9200")
        sys.exit(1)
    
    scheme = sys.argv[1]
    host = sys.argv[2]
    port = int(sys.argv[3])
    
    inspector = ElasticsearchDeepInspector(scheme, host, port)
    print(f"Starting deep analysis of {scheme}://{host}:{port}")
    
    analysis = inspector.full_analysis()
    report = format_deep_analysis_report(analysis)
    
    print(report)
    
    # Сохраняем в файл
    with open(f"deep_analysis_{host}_{port}.txt", "w", encoding="utf-8") as f:
        f.write(report)
    
    with open(f"deep_analysis_{host}_{port}.json", "w", encoding="utf-8") as f:
        # Конвертируем sets в lists для JSON
        for idx in analysis["analyzed_indices"]:
            idx["fields"] = list(idx["fields"])
            idx["sample_emails"] = list(idx["sample_emails"])
            idx["sample_phones"] = list(idx["sample_phones"])
        json.dump(analysis, f, indent=2, ensure_ascii=False)
