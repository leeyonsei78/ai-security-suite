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
      </Routes>
    </BrowserRouter>
  )
}
