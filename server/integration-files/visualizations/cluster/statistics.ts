
export default [
  {
    _id: 'tbSIEM-App-Statistics-remoted-Recv-bytes',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics remoted Recv bytes',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics remoted Recv bytes',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:remoted.recv_bytes, q='*').label(recv_bytes),.es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:remoted.recv_bytes, q='*').trend().label(Trend).lines(width=1.5)",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
  {
    _id: 'tbSIEM-App-Statistics-remoted-event-count',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics remoted event count',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics remoted event count',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:remoted.evt_count, q='*').label(evt_count),.es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:remoted.evt_count, q='*').trend().label(Trend).lines(width=1.5)",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
  {
    _id: 'tbSIEM-App-Statistics-remoted-messages',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics remoted messages',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics remoted messages',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:remoted.msg_sent, q='*').label(msg_sent),.es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:remoted.ctrl_msg_count, q='*').label(ctrl_msg_count),.es(index=tbSIEM-statistics-*,timefield=timestamp,metric=avg:remoted.discarded_count).label(discarded_count),.es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:remoted.dequeued_after_close, q='*').label(dequeued_after_close)",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
  {
    _id: 'tbSIEM-App-Statistics-remoted-tcp-sessions',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics remoted tcp sessions',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics remoted tcp sessions',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=sum:remoted.tcp_sessions, q='*').label(tcp_sessions)",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
  {
    _id: 'tbSIEM-App-Statistics-Analysisd-Overview-Events-Decoded',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics Overview events decoded',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics Overview events decode',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_events_decoded, q='*').label('Syscheck Events Decoded').bars(stack=true), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck, q='*').label('Syscollector Events Decoded').bars(stack=true), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_events_decoded, q='*').label('Rootcheck Events Decoded').bars(stack=true), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_events_decoded, q='*').label('SCA Events Decoded').bars(stack=true), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.other_events_decoded, q='*').label('Other Events Decoded').bars(stack=true), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_events_decoded, q='*').label('Host Info Events Decoded').bars(stack=true)",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
  {
    _id: 'tbSIEM-App-Statistics-Analysisd-Syscheck',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics Syscheck',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics Syscheck',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_events_decoded, q='*').label('Syscheck Events Decoded'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_edps, q='*').label('Syscheck EDPS'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_usage, q='*') ).label('Queue Usage').color('green'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_usage, q='*').if(gte, 0.7, .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_usage, q='*') ), null) .color('#FFCC11').label('Queue Usage 70%+'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_usage, q='*').if(gte, 0.9, .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_usage, q='*') ), null) .color('red').label('Queue Usage 90%+')",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
  {
    _id: 'tbSIEM-App-Statistics-Analysisd-Syscollector',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics Syscollector',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics Syscollector',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_events_decoded, q='*').label('syscollector Events Decoded'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_edps, q='*').label('syscollector EDPS'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_usage, q='*') ).label('Queue Usage').color('green'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_usage, q='*').if(gte, 0.7, .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_usage, q='*') ), null) .color('#FFCC11').label('Queue Usage 70%+'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_usage, q='*').if(gte, 0.9, .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_usage, q='*') ), null) .color('red').label('Queue Usage 90%+')",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
  {
    _id: 'tbSIEM-App-Statistics-Analysisd-Rootcheck',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics Rootcheck',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics Rootcheck',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_events_decoded, q='*').label('Rootcheck Events Decoded'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_edps, q='*').label('Rootcheck EDPS'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_usage, q='*') ).label('Queue Usage').color('green'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_usage, q='*').if(gte, 0.7, .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_usage, q='*') ), null) .color('#FFCC11').label('Queue Usage 70%+'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_usage, q='*').if(gte, 0.9, .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_usage) ), null) .color('red').label('Queue Usage 90%+')",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
  {
    _id: 'tbSIEM-App-Statistics-Analysisd-SCA',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics SCA',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics SCA',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_events_decoded, q='*').label('SCA Events Decoded'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_edps, q='*').label('SCA EDPS'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_usage, q='*') ).label('Queue Usage').color('green'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_usage, q='*').if(gte, 0.7, .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_usage, q='*') ), null) .color('#FFCC11').label('Queue Usage 70%+'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_usage, q='*').if(gte, 0.9, .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_usage, q='*') ), null) .color('red').label('Queue Usage 90%+')",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
  {
    _id: 'tbSIEM-App-Statistics-Analysisd-HostInfo',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics HostInfo',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics HostInfo',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_events_decoded, q='*').label('Host info Events Decoded'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_edps, q='*').label('Host info EDPS'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_usage, q='*') ).label('Queue Usage').color('green'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_usage, q='*').if(gte, 0.7, .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_usage, q='*') ), null) .color('#FFCC11').label('Queue Usage 70%+'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_usage, q='*').if(gte, 0.9, .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_usage, q='*') ), null) .color('red').label('Queue Usage 90%+')",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
  {
    _id: 'tbSIEM-App-Statistics-Analysisd-Other',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics Other',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics Other',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.other_events_decoded, q='*').label('Host info Events Decoded'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.other_edps, q='*').label('Host info EDPS'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_usage, q='*') ).label('Queue Usage').color('green'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_usage, q='*').if(gte, 0.7, .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_usage, q='*') ), null) .color('#FFCC11').label('Queue Usage 70%+'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_usage, q='*').if(gte, 0.9, .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_usage, q='*') ), null) .color('red').label('Queue Usage 90%+')",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },

  {
    _id: 'tbSIEM-App-Statistics-Analysisd-Events-By-Node',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics Events by Node',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics Events by Node',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=sum:analysisd.events_processed, q='*') .label('Total'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=sum:analysisd.events_processed, q='*', split=nodeName.keyword:5).label('Events processed by Node: $1','^.* > nodeName.keyword:(\\\\S+) > .*')",
          interval: '5m',
        },
        aggs: [],
      }),
      visStateByNode: JSON.stringify({
        title: 'tbSIEM App Statistics Events by Node',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=sum:analysisd.events_processed, q='*') .label('Events processed by Node: NODE_NAME')",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
  {
    _id: 'tbSIEM-App-Statistics-Analysisd-Events-Dropped-By-Node',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics Events Dropped by Node',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics Events Dropped by Node',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=sum:analysisd.events_dropped, q='*') .label('Total'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=sum:analysisd.events_dropped, q='*', split=nodeName.keyword:5).label('Events dropped by Node: $1','^.* > nodeName.keyword:(\\\\S+) > .*')",
          interval: '5m',
        },
        aggs: [],
      }),
      visStateByNode: JSON.stringify({
        title: 'tbSIEM App Statistics Events by Node',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=sum:analysisd.events_dropped, q='*') .label('Events dropped by Node: NODE_NAME')",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
  {
    _id: 'tbSIEM-App-Statistics-Analysisd-Queues-Usage',
    _type: 'visualization',
    _source: {
      title: 'tbSIEM App Statistics Queues Usage',
      visState: JSON.stringify({
        title: 'tbSIEM App Statistics Queues Usage',
        type: 'timelion',
        params: {
          expression:
            ".es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.event_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.event_queue_usage, q='*') ).label('Event queue usage'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rule_matching_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.rule_matching_queue_usage, q='*') ).label('Rule matching queue usage'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.alerts_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.alerts_queue_usage, q='*') ).label('Alerts log queue usage'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.firewall_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.firewall_queue_usage, q='*') ).label('Firewall log queue usage'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.statistical_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.statistical_queue_usage, q='*') ).label('Statistical log queue usage'), .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.archives_queue_size, q='*').multiply( .es(index=tbSIEM-statistics-*, timefield=timestamp,metric=avg:analysisd.archives_queue_usage, q='*') ).label('Statistical log queue usage')",
          interval: '5m',
        },
        aggs: [],
      }),
      uiStateJSON: '{}',
      description: '',
      version: 1,
      kibanaSavedObjectMeta: {
        searchSourceJSON: JSON.stringify({
          index: 'tbSIEM-statistics-*',
          filter: [],
          query: { query: '', language: 'lucene' },
        }),
      },
    },
  },
];
