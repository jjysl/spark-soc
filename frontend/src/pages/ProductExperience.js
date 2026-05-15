(function () {
  const {useState} = React;
  const h = React.createElement;

  const plans = [
    {
      name: 'Starter',
      price: 'Per endpoint',
      fit: 'PMEs com primeira camada de monitoramento gerenciado',
      features: ['Wazuh agent onboarding', 'Core detection workflow', 'Evidence workspace', 'Monthly analyst review'],
    },
    {
      name: 'MDR',
      price: 'Per endpoint + log source',
      fit: 'Times que precisam de resposta assistida e evidência auditável',
      features: ['FortiGate containment', 'SPARK Trace', 'Evidence Pack', 'Priority response queue'],
      featured: true,
    },
    {
      name: 'Enterprise',
      price: 'Workspace contract',
      fit: 'Ambientes multi-site com integrações e governança avançadas',
      features: ['Dedicated tenant', 'Custom playbooks', 'Compliance evidence mapping', 'Executive reporting'],
    },
  ];

  const journey = [
    ['1', 'Create workspace', 'Tenant, users, roles and evidence retention are provisioned.'],
    ['2', 'Install agent', 'Endpoints start forwarding Wazuh telemetry into the MDR workflow.'],
    ['3', 'Integrate FortiGate', 'Containment connector validates API access and response policy readiness.'],
    ['4', 'Receive evidence', 'Analysts receive alerts, containment actions, SPARK Trace and Evidence Packs.'],
  ];

  function ProductExperienceApp() {
    const [message, setMessage] = useState('');

    function handleCta(kind) {
      const text = kind === 'demo'
        ? 'Demo request captured for the MDR workspace.'
        : 'Onboarding request staged: workspace, agent and FortiGate connector are the next steps.';
      setMessage(text);
    }

    return h(React.Fragment, null,
      h('div', {className: 'ph'},
        h('div', null,
          h('div', {className: 'ptitle'}, 'Product & Onboarding'),
          h('div', {className: 'psub'}, h('span', {className: 'ldot'}), 'MDR Command Center for PMEs and teams without a mature SOC')
        ),
        h('div', {className: 'ha'},
          h('button', {className: 'btn', onClick: () => handleCta('demo')}, 'Request Demo'),
          h('button', {className: 'btn btnp', onClick: () => handleCta('onboarding')}, 'Start Onboarding')
        )
      ),
      message ? h('div', {className: 'aibox'}, h('strong', null, 'Workspace CTA: '), message) : null,
      h('div', {className: 'product-hero'},
        h('div', null,
          h('span', {className: 'product-kicker'}, 'NG-SOC / MDR as a Service'),
          h('h2', null, 'Detect, decide, respond and document in one operational workspace.'),
          h('p', null, 'SPARK SOC connects Wazuh telemetry, FortiGate containment and analyst evidence into a commercial MDR workflow for customers that need security operations without building a full SOC from scratch.'),
          h('div', {className: 'product-proof-grid'},
            ['Real FortiGate Block/Unblock', 'SPARK Trace', 'Evidence Pack', 'Containment Confidence'].map(item =>
              h('span', {key: item}, item)
            )
          )
        ),
        h('div', {className: 'product-command-card'},
          h('div', {className: 'response-title'}, 'Customer Value'),
          h('div', {className: 'response-grid'},
            [
              ['Audience', 'PMEs and lean IT/security teams'],
              ['Model', 'NG-SOC / MDR as a Service'],
              ['Commercial metric', 'Endpoint or log source pricing'],
              ['Outcome', 'Actionable alerts with audit-ready evidence'],
            ].map(row => h(React.Fragment, {key: row[0]}, h('span', null, row[0]), h('strong', null, row[1])))
          )
        )
      ),
      h('div', {className: 'product-section-title'}, 'Customer Onboarding'),
      h('div', {className: 'onboarding-grid'},
        journey.map(step => h('div', {className: 'onboarding-step', key: step[0]},
          h('div', {className: 'onboarding-num'}, step[0]),
          h('div', null,
            h('div', {className: 'row-title'}, step[1]),
            h('div', {className: 'muted'}, step[2])
          )
        ))
      ),
      h('div', {className: 'product-section-title'}, 'Plans'),
      h('div', {className: 'plans-grid'},
        plans.map(plan => h('div', {className: `plan-card ${plan.featured ? 'featured' : ''}`, key: plan.name},
          h('div', {className: 'plan-head'},
            h('div', null, h('div', {className: 'plan-name'}, plan.name), h('div', {className: 'plan-fit'}, plan.fit)),
            plan.featured ? h('span', {className: 'badge blive'}, 'Recommended') : null
          ),
          h('div', {className: 'plan-price'}, plan.price),
          h('ul', {className: 'plan-features'}, plan.features.map(feature => h('li', {key: feature}, feature))),
          h('button', {className: `btn ${plan.featured ? 'btnp' : ''}`, onClick: () => handleCta('onboarding')}, 'Start Onboarding')
        ))
      ),
      h('div', {className: 'aibox'},
        h('strong', null, 'Differentiator: '),
        'SPARK does not stop at alerting. It links detection, analyst decision, FortiGate response, containment proof and compliance evidence into a repeatable MDR operating model.'
      )
    );
  }

  const root = document.getElementById('product-root');
  if (root) ReactDOM.createRoot(root).render(h(ProductExperienceApp));
})();
