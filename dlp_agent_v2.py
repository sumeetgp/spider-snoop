import re
import json
from typing import List, Dict, Any

class DLPAgent:
    def __init__(self):
        self.test_results = []
        
    def detect_sensitive_data(self, text: str) -> Dict[str, Any]:
        """Detect various types of sensitive data in text."""
        results = {
            'original_text': text,
            'findings': [],
            'risk_level': 'LOW'
        }
        
        # Credit Card Numbers
        cc_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
        cc_matches = re.findall(cc_pattern, text)
        if cc_matches:
            results['findings'].append({
                'type': 'Credit Card',
                'matches': cc_matches,
                'count': len(cc_matches)
            })
            results['risk_level'] = 'HIGH'
        
        # Social Security Numbers
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        ssn_matches = re.findall(ssn_pattern, text)
        if ssn_matches:
            results['findings'].append({
                'type': 'SSN',
                'matches': ssn_matches,
                'count': len(ssn_matches)
            })
            results['risk_level'] = 'HIGH'
        
        # Email Addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        email_matches = re.findall(email_pattern, text)
        if email_matches:
            results['findings'].append({
                'type': 'Email',
                'matches': email_matches,
                'count': len(email_matches)
            })
            if results['risk_level'] == 'LOW':
                results['risk_level'] = 'MEDIUM'
        
        # Phone Numbers
        phone_pattern = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        phone_matches = re.findall(phone_pattern, text)
        if phone_matches:
            results['findings'].append({
                'type': 'Phone Number',
                'matches': phone_matches,
                'count': len(phone_matches)
            })
            if results['risk_level'] == 'LOW':
                results['risk_level'] = 'MEDIUM'
        
        # IP Addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_matches = re.findall(ip_pattern, text)
        if ip_matches:
            results['findings'].append({
                'type': 'IP Address',
                'matches': ip_matches,
                'count': len(ip_matches)
            })
            if results['risk_level'] == 'LOW':
                results['risk_level'] = 'MEDIUM'
        
        return results
    
    def run_test(self, test_name: str, text: str) -> Dict[str, Any]:
        """Run a single test and store the result."""
        result = self.detect_sensitive_data(text)
        result['test_name'] = test_name
        
        # Store the result for later printing
        self.test_results.append(result)
        
        return result
    
    def run_all_tests(self) -> None:
        """Run all predefined tests."""
        test_cases = [
            {
                'name': 'Test 1: Credit Card Detection',
                'text': 'Please charge my credit card 4532-1234-5678-9012 for the purchase.'
            },
            {
                'name': 'Test 2: SSN Detection',
                'text': 'My social security number is 123-45-6789 for verification.'
            },
            {
                'name': 'Test 3: Email Detection',
                'text': 'Contact me at john.doe@example.com or jane.smith@company.org'
            },
            {
                'name': 'Test 4: Mixed Sensitive Data',
                'text': 'Customer info: Email: user@test.com, Phone: 555-123-4567, SSN: 987-65-4321, Card: 5555 4444 3333 2222'
            },
            {
                'name': 'Test 5: Clean Text',
                'text': 'This is a normal text without any sensitive information.'
            },
            {
                'name': 'Test 6: IP Address Detection',
                'text': 'The server is located at 192.168.1.100 and backup at 10.0.0.1'
            }
        ]
        
        # Run all tests and store results
        for test_case in test_cases:
            self.run_test(test_case['name'], test_case['text'])
    
    def print_all_results(self) -> None:
        """Print all test results after all tests are completed."""
        print("=" * 80)
        print("DLP AGENT - ALL TEST RESULTS")
        print("=" * 80)
        
        for i, result in enumerate(self.test_results, 1):
            print(f"\n{'-' * 60}")
            print(f"TEST {i}: {result['test_name']}")
            print(f"{'-' * 60}")
            
            print(f"Original Text: {result['original_text']}")
            print(f"Risk Level: {result['risk_level']}")
            
            if result['findings']:
                print("Sensitive Data Found:")
                for finding in result['findings']:
                    print(f"  • {finding['type']}: {finding['count']} instance(s)")
                    for match in finding['matches']:
                        print(f"    - {match}")
            else:
                print("No sensitive data detected.")
        
        # Print summary
        print(f"\n{'=' * 80}")
        print("SUMMARY")
        print(f"{'=' * 80}")
        
        total_tests = len(self.test_results)
        high_risk = sum(1 for r in self.test_results if r['risk_level'] == 'HIGH')
        medium_risk = sum(1 for r in self.test_results if r['risk_level'] == 'MEDIUM')
        low_risk = sum(1 for r in self.test_results if r['risk_level'] == 'LOW')
        
        print(f"Total Tests Run: {total_tests}")
        print(f"High Risk: {high_risk}")
        print(f"Medium Risk: {medium_risk}")
        print(f"Low Risk: {low_risk}")
        
        # Get all unique finding types
        all_findings = {}
        for result in self.test_results:
            for finding in result['findings']:
                finding_type = finding['type']
                if finding_type in all_findings:
                    all_findings[finding_type] += finding['count']
                else:
                    all_findings[finding_type] = finding['count']
        
        if all_findings:
            print("\nSensitive Data Types Found:")
            for data_type, count in all_findings.items():
                print(f"  • {data_type}: {count} total instances")

def main():
    # Initialize the DLP agent
    dlp_agent = DLPAgent()
    
    print("Running DLP tests...")
    print("Please wait while all tests complete...")
    
    # Run all tests (results are stored internally)
    dlp_agent.run_all_tests()
    
    # Print all results after all tests are complete
    dlp_agent.print_all_results()

if __name__ == "__main__":
    main()