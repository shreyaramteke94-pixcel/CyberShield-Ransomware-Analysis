export type ThreatLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
export type Verdict = 'MALICIOUS' | 'SUSPICIOUS' | 'SAFE';
export type DecryptionFeasibility = 'DECRYPTABLE' | 'PARTIALLY_DECRYPTABLE' | 'UNSUPPORTED' | 'NOT_APPLICABLE';

export interface PESection {
  name: string;
  virtualSize: string;
  rawSize: string;
  entropy: number;
  characteristics: string;
  status: 'SUSPICIOUS' | 'NORMAL' | 'ANOMALOUS';
}

export interface ProcessActivity {
  pid: number;
  name: string;
  action: string;
  status: 'MALICIOUS' | 'WARNING' | 'NEUTRAL';
  timestamp: string;
}

export interface NetworkBeacon {
  ip: string;
  domain: string;
  port: number;
  protocol: string;
  country: string;
  action: string;
}

export interface MitreTactic {
  id: string;
  name: string;
  phase: string;
  technique: string;
  description: string;
  detected: boolean;
}

export interface MLFeature {
  feature: string;
  weight: number;
  influence: 'Malicious' | 'Safe';
  description: string;
}

export interface SampleAnalysis {
  id: string;
  fileName: string;
  fileSize: string;
  fileType: string;
  uploadedAt: string;
  analyzedAt: string;
  md5: string;
  sha256: string;
  sha1: string;
  ssdeep: string;
  entropy: number;
  verdict: Verdict;
  threatLevel: ThreatLevel;
  confidenceScore: number;
  ransomwareFamily: string;
  decryptionStatus: DecryptionFeasibility;
  decryptionMethod: string;
  decryptionKeyCandidate?: string;
  decryptionSuccessRate?: number;
  sampleNote?: string;
  threatSummary: string;
  tags: string[];

  // Static Analysis
  staticAnalysis: {
    isPacked: boolean;
    packerName?: string;
    compiler: string;
    subsystem: string;
    architecture: string;
    imphash: string;
    sections: PESection[];
    suspiciousStrings: string[];
    importedDlls: { dll: string; functions: string[] }[];
    exports: string[];
    antiDebugDetected: boolean;
    antiVMDetection: boolean;
  };

  // Dynamic Analysis
  dynamicAnalysis: {
    behaviorScore: number; // 0 - 100
    executionTime: string;
    sandboxOS: string;
    fileModifications: string[];
    registryKeys: string[];
    processTree: ProcessActivity[];
    networkBeacons: NetworkBeacon[];
    mutexes: string[];
    ransomNoteFound: boolean;
    ransomNotePath?: string;
    ransomNoteContent?: string;
    shadowCopiesDeleted: boolean;
    bootConfigAltered: boolean;
  };

  // Crypto Analysis
  cryptoAnalysis: {
    encryptionAlgorithm: string;
    keySize: string;
    mode: string;
    prngFlawDetected: boolean;
    flawDescription: string;
    weakIvDetected: boolean;
    keyScheduleFlaw: boolean;
    memoryLeakKey: boolean;
    encryptionSpeed: string;
    targetedExtensions: string[];
  };

  // ML Classification
  mlClassification: {
    modelName: string;
    familyProbabilities: { family: string; probability: number }[];
    topFeatures: MLFeature[];
    anomalyScore: number;
  };

  mitreTactics: MitreTactic[];
  iocs: {
    hashes: string[];
    ips: string[];
    domains: string[];
    registry: string[];
    yaraRuleName: string;
    yaraRuleText: string;
  };
  remediation: string[];
}

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: 'Lead SOC Analyst' | 'Threat Researcher' | 'Incident Responder' | 'Security Admin';
  avatar: string;
  badge: string;
  lastLogin: string;
  analysesCount: number;
}

export interface ThreatFeedItem {
  id: string;
  title: string;
  variant: string;
  severity: ThreatLevel;
  date: string;
  cve?: string;
  source: string;
  targetIndustries: string[];
  summary: string;
  indicatorCount: number;
}

export interface AdminStats {
  totalUsers: number;
  activeUsers: number;
  totalAnalyses: number;
  successfulAnalyses: number;
  failedAnalyses: number;
  sandboxNodesOnline: number;
  avgAnalysisTime: string;
  storageUsed: string;
}
