import { z } from 'zod';

// Schema for vulnerability records
export const VulnerabilityRecordSchema = z.object({
  cve_id: z.string().regex(/^CVE-\d{4}-\d+$/),
  title: z.string(),
  processed_title: z.string(),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  description: z.string(),
  vendor: z.string(),
  product: z.string(),
  cpes: z.array(z.string()),
  exploit_examples_url: z.array(z.string().url()),
  published_date: z.string(),
  updated_date: z.string(),
  vulnerability_date: z.string(),
});

export type VulnerabilityRecord = z.infer<typeof VulnerabilityRecordSchema>;

// Mock database of vulnerabilities
const vulnerabilitiesDb: VulnerabilityRecord[] = [
  {
    cve_id: 'CVE-2025-53770',
    title: 'Microsoft SharePoint Server Deserialization RCE Vulnerability',
    processed_title: 'SharePoint Deserialization RCE',
    severity: 'critical',
    description:
      'SharePoint Server untrusted data deserialization grants unauthenticated attackers remote code execution over the network, bypassing a critical security patch.',
    vendor: 'Microsoft',
    product: 'Microsoft SharePoint Server',
    cpes: [
      'cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:subscription:*:*:*',
      'cpe:2.3:a:microsoft:sharepoint_server:2016:*:*:*:enterprise:*:*:*',
      'cpe:2.3:a:microsoft:sharepoint_server:2019:*:*:*:*:*:*:*',
    ],
    exploit_examples_url: [
      'https://arstechnica.com/security/2025/07/sharepoint-vulnerability-with-9-8-severity-rating-is-under-exploit-across-the-globe/',
      'https://www.bleepingcomputer.com/news/microsoft/microsoft-sharepoint-zero-day-exploited-in-rce-attacks-no-patch-available/',
    ],
    published_date: '2025-07-19T00:00:00Z',
    updated_date: '2025-07-21T00:00:00Z',
    vulnerability_date: '2025-07-18 18:00:00',
  },
  {
    cve_id: 'CVE-2024-21762',
    title: 'Fortinet FortiOS SSL VPN Out-of-Bounds Write Vulnerability',
    processed_title: 'FortiOS SSL VPN RCE',
    severity: 'critical',
    description:
      'A out-of-bounds write vulnerability in FortiOS SSL VPN may allow a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests.',
    vendor: 'Fortinet',
    product: 'FortiOS',
    cpes: [
      'cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*',
    ],
    exploit_examples_url: [
      'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    ],
    published_date: '2024-02-09T00:00:00Z',
    updated_date: '2024-02-12T00:00:00Z',
    vulnerability_date: '2024-02-08 12:00:00',
  },
  {
    cve_id: 'CVE-2023-22515',
    title: 'Atlassian Confluence Data Center Broken Access Control Vulnerability',
    processed_title: 'Confluence Privilege Escalation',
    severity: 'critical',
    description:
      'Atlassian Confluence Data Center and Server contains a broken access control vulnerability that allows an attacker to create unauthorized Confluence administrator accounts and access Confluence instances.',
    vendor: 'Atlassian',
    product: 'Confluence Data Center',
    cpes: [
      'cpe:2.3:a:atlassian:confluence_data_center:*:*:*:*:*:*:*:*',
      'cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:*:*:*',
    ],
    exploit_examples_url: [
      'https://confluence.atlassian.com/security/cve-2023-22515-broken-access-control-vulnerability-in-confluence-data-center-and-server-1295682276.html',
    ],
    published_date: '2023-10-04T00:00:00Z',
    updated_date: '2023-10-06T00:00:00Z',
    vulnerability_date: '2023-10-04 09:00:00',
  },
  {
    cve_id: 'CVE-2021-44228',
    title: 'Apache Log4j Remote Code Execution Vulnerability',
    processed_title: 'Log4Shell RCE',
    severity: 'critical',
    description:
      'Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
    vendor: 'Apache',
    product: 'Log4j',
    cpes: [
      'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
    ],
    exploit_examples_url: [
      'https://logging.apache.org/log4j/2.x/security.html',
      'https://www.lunasec.io/docs/blog/log4j-zero-day/',
    ],
    published_date: '2021-12-10T00:00:00Z',
    updated_date: '2021-12-14T00:00:00Z',
    vulnerability_date: '2021-12-09 12:00:00',
  },
];

/**
 * Fetch a vulnerability record by CVE ID
 */
export async function getVulnerabilityByCveId(
  cveId: string
): Promise<VulnerabilityRecord | null> {
  // Simulate async database lookup
  await new Promise((resolve) => setTimeout(resolve, 100));

  const normalized = cveId.toUpperCase();
  const record = vulnerabilitiesDb.find((v) => v.cve_id === normalized);
  return record || null;
}

/**
 * Get all available CVE IDs
 */
export async function listAvailableCveIds(): Promise<string[]> {
  await new Promise((resolve) => setTimeout(resolve, 50));
  return vulnerabilitiesDb.map((v) => v.cve_id);
}

/**
 * Validate CVE ID format
 */
export function isValidCveId(cveId: string): boolean {
  return /^CVE-\d{4}-\d+$/i.test(cveId);
}
