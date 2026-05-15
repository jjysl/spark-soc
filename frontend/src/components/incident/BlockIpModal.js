(function () {
  const h = React.createElement;

  function BlockIpModal({open, target, defaultReason, action, onClose, onSubmit}) {
    const [reason, setReason] = React.useState(defaultReason || '');
    const [duration, setDuration] = React.useState(60);
    React.useEffect(() => setReason(defaultReason || ''), [defaultReason, open]);
    const Modal = window.SparkComponents.Modal;
    const validReason = reason.trim().length >= 10;
    return h(Modal, {
      open,
      title: 'Block IP with FortiGate',
      onClose,
      footer: h('div', {className: 'row-actions'},
        h('button', {className: 'btn', onClick: onClose}, 'Cancel'),
        h('button', {
          className: 'btn btn-danger',
          disabled: action?.loading || !validReason,
          onClick: () => onSubmit({reason, duration_minutes: duration}),
        }, action?.loading ? 'Blocking...' : 'Confirm Block')
      ),
    },
      h('div', {className: 'form-stack'},
        h('label', null, 'IP address'),
        h('input', {className: 'form-input mono containment-target', readOnly: true, value: target?.ip || ''}),
        h('label', null, 'Incident context'),
        h('input', {className: 'form-input', readOnly: true, value: target?.title || target?.case_id || 'Manual containment'}),
        h('label', null, 'Reason'),
        h('textarea', {className: 'form-input', rows: 4, value: reason, onChange: event => setReason(event.target.value), placeholder: 'Describe the containment justification for the audit trail'}),
        h('div', {className: validReason ? 'empty-detail' : 'form-warning'}, validReason ? 'Justification accepted for audit evidence.' : 'Enter at least 10 characters to confirm containment.'),
        h('label', null, 'Duration minutes'),
        h('input', {className: 'form-input mono', type: 'number', min: 5, max: 1440, value: duration, onChange: event => setDuration(Number(event.target.value || 60))}),
        h('div', {className: 'empty-detail'}, 'Creates/updates the SPARK_BLOCK object, adds it to SPARK_BLOCKLIST, validates SPARK_AUTO_BLOCK, and records audit evidence.')
      )
    );
  }

  window.SparkIncident = window.SparkIncident || {};
  window.SparkIncident.BlockIpModal = BlockIpModal;
})();
