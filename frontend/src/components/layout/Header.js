(function () {
  const h = React.createElement;

  function Header({user, clock, onLogout}) {
    return h('header', {className: 'topbar app-topbar'},
      h('div', {className: 'brand'},
        h('div', {className: 'bmark'}, 'S'),
        h('div', null,
          h('div', {className: 'bname'}, 'SPARK SOC'),
          h('div', {className: 'bsub'}, 'NG-SOC as a Service')
        )
      ),
      h('div', {className: 'tr'},
        h('div', {className: 'spill'}, h('span', {className: 'sdot sg'}), 'Live lab'),
        h('div', {className: 'mts'}, clock || '--:--:-- UTC'),
        h('div', {className: 'user-pill'},
          h('span', {className: 'av'}, user?.avatar || 'SC'),
          h('span', null, user?.name || user?.username || 'SOC Analyst'),
          h('span', {className: 'muted'}, user?.role || 'analyst')
        ),
        h('button', {className: 'btn', onClick: onLogout}, 'Logout')
      )
    );
  }

  window.SparkLayout = window.SparkLayout || {};
  window.SparkLayout.Header = Header;
})();
