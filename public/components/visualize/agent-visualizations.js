/*
 * Wazuh app - Agents visualizations
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

export const agentVisualizations = {
  general: {
    rows: [
      {
        height: 400,
        vis: [
          {
            title: 'Alert groups evolution',
            id: 'tbSIEM-App-Agents-General-Alert-groups-evolution',
            width: 50
          },
          { title: 'Alerts', id: 'tbSIEM-App-Agents-General-Alerts', width: 50 }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: 'Top 5 alerts',
            id: 'tbSIEM-App-Agents-General-Top-5-alerts',
            width: 33
          },
          {
            title: 'Top 5 rule groups',
            id: 'tbSIEM-App-Agents-General-Top-10-groups',
            width: 33
          },
          {
            title: 'Top 5 PCI DSS Requirements',
            id: 'tbSIEM-App-Agents-General-Top-5-PCI-DSS-Requirements',
            width: 34
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-General-Alerts-summary',
            width: 60
          },
          {
            title: 'Groups summary',
            id: 'tbSIEM-App-Agents-General-Groups-summary',
            width: 40
          }
        ]
      }
    ]
  },
  aws: {
    rows: [
      {
        height: 250,
        vis: [
          {
            title: 'Sources',
            id: 'tbSIEM-App-Agents-AWS-Top-sources',
            width: 25
          },
          {
            title: 'Accounts',
            id: 'tbSIEM-App-Agents-AWS-Top-accounts',
            width: 25
          },
          {
            title: 'S3 buckets',
            id: 'tbSIEM-App-Agents-AWS-Top-buckets',
            width: 25
          },
          {
            title: 'Regions',
            id: 'tbSIEM-App-Agents-AWS-Top-regions',
            width: 25
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: 'Events by source over time',
            id: 'tbSIEM-App-Agents-AWS-Events-by-source',
            width: 50
          },
          {
            title: 'Events by S3 bucket over time',
            id: 'tbSIEM-App-Agents-AWS-Events-by-s3-bucket',
            width: 50
          }
        ]
      },
      {
        height: 570,
        vis: [
          {
            title: 'Geolocation map',
            id: 'tbSIEM-App-Agents-AWS-geo'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-AWS-Alerts-summary'
          }
        ]
      }
    ]
  },
  fim: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: 'Most active users',
            id: 'tbSIEM-App-Agents-FIM-Users',
            width: 25
          },
          {
            title: 'Actions',
            id: 'tbSIEM-App-Agents-FIM-Actions',
            width: 25
          },
          {
            title: 'Events',
            id: 'tbSIEM-App-Agents-FIM-Events',
            width: 50
          }
        ]
      },
      {
        height: 230,
        vis: [
          {
            title: 'Files added',
            id: 'tbSIEM-App-Agents-FIM-Files-added',
            width: 33
          },
          {
            title: 'Files modified',
            id: 'tbSIEM-App-Agents-FIM-Files-modified',
            width: 33
          },
          {
            title: 'Files deleted',
            id: 'tbSIEM-App-Agents-FIM-Files-deleted',
            width: 34
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-FIM-Alerts-summary'
          }
        ]
      }
    ]
  },
  gcp: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: 'Top 5 rules',
            id: 'tbSIEM-App-Agents-GCP-Top-5-rules',
            width: 50
          },
          {
            title: 'Top query events',
            id: 'tbSIEM-App-Agents-GCP-Event-Query-Name',
            width: 25
          },
          {
            title: 'Top 5 instances',
            id: 'tbSIEM-App-Agents-GCP-Top-5-instances',
            width: 25
          },
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: 'Top project id by sourcetype',
            id: 'tbSIEM-App-Agents-GCP-Top-ProjectId-By-SourceType',
            width: 25
          },
          {
            title: 'GCP alerts evolution',
            id: 'tbSIEM-App-Agents-GCP-Events-Over-Time',
            width: 75
          },
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: 'Auth answer count',
            id: 'tbSIEM-App-Agents-GCP-authAnswer-Bar',
            width: 40
          },
          {
            title: 'Resource type by project id',
            id: 'tbSIEM-App-Agents-GCP-Top-ResourceType-By-Project-Id',
            width: 60
          },
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-GCP-Alerts-summary'
          }
        ]
      }
    ]
  },
  pci: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: 'Top 5 rule groups',
            id: 'tbSIEM-App-Agents-PCI-Groups',
            width: 33
          },
          {
            title: 'Top 5 rules',
            id: 'tbSIEM-App-Agents-PCI-Rule',
            width: 33
          },
          {
            title: 'Top 5 PCI DSS requirements',
            id: 'tbSIEM-App-Agents-PCI-Requirement',
            width: 34
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: 'PCI Requirements',
            id: 'tbSIEM-App-Agents-PCI-Requirements',
            width: 75
          },
          {
            title: 'Rule level distribution',
            id: 'tbSIEM-App-Agents-PCI-Rule-level-distribution',
            width: 25
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-PCI-Last-alerts'
          }
        ]
      }
    ]
  },
  gdpr: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: 'Top 5 rule groups',
            id: 'tbSIEM-App-Agents-GDPR-Groups',
            width: 33
          },
          {
            title: 'Top 5 rules',
            id: 'tbSIEM-App-Agents-GDPR-Rule',
            width: 33
          },
          {
            title: 'Top 5 GDPR requirements',
            id: 'tbSIEM-App-Agents-GDPR-Requirement',
            width: 34
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: 'GDPR Requirements',
            id: 'tbSIEM-App-Agents-GDPR-Requirements',
            width: 75
          },
          {
            title: 'Rule level distribution',
            id: 'tbSIEM-App-Agents-GDPR-Rule-level-distribution',
            width: 25
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-GDPR-Last-alerts'
          }
        ]
      }
    ]
  },
  nist: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: 'Stats',
            id: 'tbSIEM-App-Agents-NIST-Stats',
            width: 25
          },
          {
            title: 'Top 10 requirements',
            id: 'tbSIEM-App-Agents-NIST-top-10-requirements',
            width: 25
          },
          {
            title: 'Requirements distributed by level',
            id: 'tbSIEM-App-Agents-NIST-Requirement-by-level',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: 'Requirements over time',
            id: 'tbSIEM-App-Agents-NIST-Requirements-stacked-overtime'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-NIST-Last-alerts'
          }
        ]
      }
    ]
  },
  tsc: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: 'Top 5 rule groups',
            id: 'tbSIEM-App-Agents-TSC-Groups',
            width: 33
          },
          {
            title: 'Top 5 rules',
            id: 'tbSIEM-App-Agents-TSC-Rule',
            width: 33
          },
          {
            title: 'Top 5 TSC requirements',
            id: 'tbSIEM-App-Agents-TSC-Requirement',
            width: 34
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: 'TSC Requirements',
            id: 'tbSIEM-App-Agents-TSC-Requirements',
            width: 75
          },
          {
            title: 'Rule level distribution',
            id: 'tbSIEM-App-Agents-TSC-Rule-level-distribution',
            width: 25
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Overview-TSC-Alerts-summary'
          }
        ]
      }
    ]
  },
  hipaa: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: 'Requirements over time',
            id: 'tbSIEM-App-Agents-HIPAA-Requirements-Stacked-Overtime',
            width: 50
          },
          {
            title: 'Top 10 requirements',
            id: 'tbSIEM-App-Agents-HIPAA-top-10',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: 'HIPAA requirements',
            id: 'tbSIEM-App-Agents-HIPAA-Burbles',
            width: 50
          },
          {
            title: 'Requirements distribution by level',
            id: 'tbSIEM-App-Agents-HIPAA-Distributed-By-Level',
            width: 25
          },
          {
            title: 'Most common alerts',
            id: 'tbSIEM-App-Agents-HIPAA-Most-Common',
            width: 25
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-HIPAA-Last-alerts'
          }
        ]
      }
    ]
  },
  virustotal: {
    rows: [
      {
        height: 250,
        vis: [
          {
            title: 'Last scanned files',
            id: 'tbSIEM-App-Agents-Virustotal-Last-Files-Pie',
            width: 25
          },
          {
            title: 'Malicious files alerts Evolution',
            id: 'tbSIEM-App-Agents-Virustotal-Malicious-Evolution',
            width: 75
          }
        ]
      },
      {
        height: 570,
        vis: [
          {
            title: 'Last files',
            id: 'tbSIEM-App-Agents-Virustotal-Files-Table'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-Virustotal-Alerts-summary'
          }
        ]
      }
    ]
  },
  osquery: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: 'Most common Osquery actions',
            id: 'tbSIEM-App-Agents-Osquery-most-common-osquery-actions',
            width: 25
          },
          {
            title: 'Evolution of Osquery events per pack over time',
            id: 'tbSIEM-App-Agents-Osquery-Evolution',
            width: 75
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: 'Most common Osquery packs being used',
            id: 'tbSIEM-App-Agents-Osquery-top-5-packs-being-used',
            width: 25
          },
          {
            title: 'Most common rules',
            id: 'tbSIEM-App-Agents-Osquery-monst-common-rules-being-fired',
            width: 75
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Overview-Osquery-Alerts-summary'
          }
        ]
      }
    ]
  },
  mitre: {
    rows: [
      {
        height: 360,
        vis: [
          {
            title: 'Alerts evolution over time',
            id: 'tbSIEM-App-Agents-MITRE-Alerts-Evolution',
            width: 70
          },
          {
            title: 'Top tactics',
            id: 'tbSIEM-App-Agents-MITRE-Top-Tactics',
            width: 30
          }
        ]
      },
      {
        height: 360,
        vis: [
          {
            title: 'Rule level by attack',
            id: 'tbSIEM-App-Agents-MITRE-Level-By-Attack',
            width: 33
          },
          {
            title: 'MITRE attacks by tactic',
            id: 'tbSIEM-App-Agents-MITRE-Attacks-By-Tactic',
            width: 34
          },
          {
            title: 'Rule level by tactic',
            id: 'tbSIEM-App-Agents-MITRE-Level-By-Tactic',
            width: 34
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-MITRE-Alerts-summary'
          }
        ]
      }
    ]
  },
  docker: {
    rows: [
      {
        height: 300,
        vis: [
          {
            title: 'Top 5 images',
            id: 'tbSIEM-App-Agents-Docker-top-5-images',
            width: 25
          },
          {
            title: 'Top 5 events',
            id: 'tbSIEM-App-Agents-Docker-top-5-actions',
            width: 25
          },
          {
            title: 'Resources usage over time',
            id: 'tbSIEM-App-Agents-Docker-Types-over-time',
            width: 50
          }
        ]
      },
      {
        height: 300,
        vis: [
          {
            title: 'Events occurred evolution',
            id: 'tbSIEM-App-Agents-Docker-Actions-over-time'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-Docker-Events-summary'
          }
        ]
      }
    ]
  },
  oscap: {
    rows: [
      {
        height: 230,
        vis: [
          {
            title: 'Top 5 Scans',
            id: 'tbSIEM-App-Agents-OSCAP-Scans',
            width: 25
          },
          {
            title: 'Top 5 Profiles',
            id: 'tbSIEM-App-Agents-OSCAP-Profiles',
            width: 25
          },
          {
            title: 'Top 5 Content',
            id: 'tbSIEM-App-Agents-OSCAP-Content',
            width: 25
          },
          {
            title: 'Top 5 Severity',
            id: 'tbSIEM-App-Agents-OSCAP-Severity',
            width: 25
          }
        ]
      },
      {
        height: 230,
        vis: [
          {
            title: 'Daily scans evolution',
            id: 'tbSIEM-App-Agents-OSCAP-Daily-scans-evolution'
          }
        ]
      },
      {
        height: 250,
        vis: [
          {
            title: 'Top 5 - Alerts',
            id: 'tbSIEM-App-Agents-OSCAP-Top-5-Alerts',
            width: 50
          },
          {
            title: 'Top 5 - High risk alerts',
            id: 'tbSIEM-App-Agents-OSCAP-Top-5-High-risk-alerts',
            width: 50
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-OSCAP-Last-alerts'
          }
        ]
      }
    ]
  },
  ciscat: {
    rows: [
      {
        height: 320,
        vis: [
          {
            title: 'Top 5 CIS-CAT groups',
            id: 'Wazuh-app-Agents-CISCAT-top-5-groups',
            width: 60
          },
          {
            title: 'Scan result evolution',
            id: 'Wazuh-app-Agents-CISCAT-scan-result-evolution',
            width: 40
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'Wazuh-app-Agents-CISCAT-alerts-summary'
          }
        ]
      }
    ]
  },
  pm: {
    rows: [
      {
        height: 290,
        vis: [
          {
            title: 'Alerts over time',
            id: 'tbSIEM-App-Agents-PM-Events-over-time',
            width: 50
          },
          {
            title: 'Rule distribution',
            id: 'tbSIEM-App-Agents-PM-Top-5-rules',
            width: 50
          }
        ]
      },
      {
        height: 240,
        vis: [
          {
            title: 'Events per control type evolution',
            id: 'tbSIEM-App-Agents-PM-Events-per-agent-evolution'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-PM-Alerts-summary'
          }
        ]
      }
    ]
  },
  audit: {
    rows: [
      {
        height: 250,
        vis: [
          {
            title: 'Groups',
            id: 'tbSIEM-App-Agents-Audit-Groups',
            width: 33
          },
          {
            title: 'Commands',
            id: 'tbSIEM-App-Agents-Audit-Commands',
            width: 33
          },
          {
            title: 'Files',
            id: 'tbSIEM-App-Agents-Audit-Files',
            width: 34
          }
        ]
      },
      {
        height: 310,
        vis: [
          {
            title: 'Alerts over time',
            id: 'tbSIEM-App-Agents-Audit-Alerts-over-time'
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Agents-Audit-Last-alerts'
          }
        ]
      }
    ]
  },
  github: {
    rows: [
      {
        height: 360,
        vis: [
          {
            title: 'Alerts evolution by organization',
            id: 'tbSIEM-App-Overview-GitHub-Alerts-Evolution-By-Organization',
            width: 60
          },
          {
            title: 'Top 5 organizations by alerts',
            id: 'tbSIEM-App-Overview-GitHub-Top-5-Organizations-By-Alerts',
            width: 40
          }
        ]
      },
      {
        height: 360,
        vis: [
          {
            title: 'Top alerts by action type and organization',
            id: 'tbSIEM-App-Overview-GitHub-Alert-Action-Type-By-Organization',
            width: 40
          },
          {
            title: 'Users with more alerts',
            id: 'tbSIEM-App-Overview-GitHub-Users-With-More-Alerts',
            width: 60
          }
        ]
      },
      {
        hide: true,
        vis: [
          {
            title: 'Alerts summary',
            id: 'tbSIEM-App-Overview-GitHub-Alert-Summary',
          }
        ]
      }
    ]
  },
};
