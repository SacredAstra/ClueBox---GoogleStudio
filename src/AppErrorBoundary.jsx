import React from 'react';

const NAVIGATION_KEY = 'forensiai.navigation.v1';

class AppErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, message: '' };
  }

  static getDerivedStateFromError(error) {
    return {
      hasError: true,
      message: error?.message || 'An unexpected rendering error interrupted the forensic workspace.',
    };
  }

  componentDidCatch(error) {
    console.error('ClueBox Odyssey recovery boundary caught an error:', error);
  }

  handleRetry = () => {
    this.setState({ hasError: false, message: '' });
  };

  handleResetNavigation = () => {
    try {
      window.sessionStorage.removeItem(NAVIGATION_KEY);
    } catch {
      // Ignore storage failures during recovery.
    }
    this.setState({ hasError: false, message: '' });
  };

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    return (
      <main className="app-recovery" role="alert">
        <div>
          <p className="eyebrow">WORKSPACE RECOVERY</p>
          <h1>ClueBox Odyssey paused to protect your session</h1>
          <p>
            {this.state.message} Your local encrypted evidence vault in IndexedDB was not modified.
          </p>
          <div className="app-recovery-actions">
            <button type="button" onClick={this.handleRetry}>
              Retry workspace
            </button>
            <button type="button" onClick={this.handleResetNavigation}>
              Return to welcome screen
            </button>
          </div>
        </div>
      </main>
    );
  }
}

export default AppErrorBoundary;
