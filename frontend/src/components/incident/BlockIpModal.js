(function () {
  const h = React.createElement;

  function BlockIpModal({open, target, defaultReason, action, onClose, onSubmit}) {
    const [reason, setReason] = React.useState(defaultReason || '');
    React.useEffect(() => setReason(defaultReason || ''), [defaultReason, open]);
    const Modal = window.SparkComponents.Modal;
    const ActionButton = window.SparkComponents.ActionButton;
    return h(Modal, {
      open,
      title: 'Block IP with FortiGate',
      onClose,
      footer: h('div', {className: 'row-actions'},
        h('button', {className: 'btn', onClick: onClose}, 'Cancel'),
        h(ActionButton, {variant: 'primary', loading: action?.loading, onClick: () => onSubmit(reason)}, 'Block IP')
      ),
    },
      h('div', {className: 'form-stack'},
        h('label', null, 'IP address'),
        h('input', {className: 'form-input mono', readOnly: true, value: target?.ip || ''}),
        h('label', null, 'Reason'),
        h('textarea', {className: 'form-input', rows: 4, value: reason, onChange: event => setReason(event.target.value)}),
        h('div', {className: 'empty-detail'}, 'Creates/updates the SPARK_BLOCK object, adds it to SPARK_BLOCKLIST, and records audit evidence.')
      )
    );
  }

  window.SparkIncident = window.SparkIncident || {};
  window.SparkIncident.BlockIpModal = BlockIpModal;
})();
