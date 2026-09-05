import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import axios from 'axios'
import NavBar from './components/NavBar'
import Dashboard from './pages/Dashboard'
import PhishingDetector from './pages/PhishingDetector'
import VulnerabilityScanner from './pages/VulnerabilityScanner'
import IoCAnalyzer from './pages/IoCAnalyzer'
import IncidentResponse from './pages/IncidentResponse'
import WebScanner from './pages/WebScanner'
import ThreatAnalysis from './pages/ThreatAnalysis'
import PromptInjectionDetector from './pages/PromptInjectionDetector'
import PwnLab from './pages/PwnLab'
import WebArena from './pages/WebArena'
import SecurityPolicyGenerator from './pages/SecurityPolicyGenerator'
import ModelAudit from './pages/ModelAudit'
import PentestLab from './pages/PentestLab'
import PhishingSimGenerator from './pages/PhishingSimGenerator'
import CveLookup from './pages/CveLookup'
import FirewallAudit from './pages/FirewallAudit'
import InfraScanner from './pages/InfraScanner'
import IamAudit from './pages/IamAudit'
import SecretScanner from './pages/SecretScanner'
import ContainerAudit from './pages/ContainerAudit'
import DnsSecurityCheck from './pages/DnsSecurityCheck'
import RiskDashboard from './pages/RiskDashboard'
import AttackMonitor from './pages/AttackMonitor'
import FsiCspAudit from './pages/FsiCspAudit'

export default function App() {
  const [isMock, setIsMock] = useState(null)

  useEffect(() => {
    axios.get('/api/mode').then(r => setIsMock(r.data.mock)).catch(() => setIsMock(true))
  }, [])

  return (
    <BrowserRouter>
      <NavBar isMock={isMock} />
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/phishing" element={<PhishingDetector />} />
        <Route path="/vuln" element={<VulnerabilityScanner />} />
        <Route path="/ioc" element={<IoCAnalyzer />} />
        <Route path="/incident" element={<IncidentResponse />} />
        <Route path="/webscan" element={<WebScanner />} />
        <Route path="/threat" element={<ThreatAnalysis />} />
        <Route path="/injection" element={<PromptInjectionDetector />} />
        <Route path="/pwn-lab" element={<PwnLab />} />
        <Route path="/web-arena" element={<WebArena />} />
        <Route path="/policy" element={<SecurityPolicyGenerator />} />
        <Route path="/model-audit" element={<ModelAudit />} />
        <Route path="/pentest-lab" element={<PentestLab />} />
        <Route path="/phishing-sim" element={<PhishingSimGenerator />} />
        <Route path="/cve-lookup" element={<CveLookup />} />
        <Route path="/firewall-audit" element={<FirewallAudit />} />
        <Route path="/infra-scan" element={<InfraScanner />} />
        <Route path="/iam-audit" element={<IamAudit />} />
        <Route path="/secret-scan" element={<SecretScanner />} />
        <Route path="/container-audit" element={<ContainerAudit />} />
        <Route path="/dns-security" element={<DnsSecurityCheck />} />
        <Route path="/risk-dashboard" element={<RiskDashboard />} />
        <Route path="/attack-monitor" element={<AttackMonitor />} />
        <Route path="/fsi-csp-audit" element={<FsiCspAudit />} />
      </Routes>
    </BrowserRouter>
  )
}
