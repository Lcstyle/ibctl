// Which State-tab transport buttons a Gateway will act on in its current state.
//
// STOP parks a Gateway in WaitingForLaunch, and START is honoured only from
// there. Shutdown is what EXIT leaves behind: the process is ending, so there
// is nothing to stop and START is ignored (ibctl state_machine dispatch_command).
// PAUSE and RESUME gate the state machine, so RESUME is offered whenever it is
// paused, stopped or not.
(function (root) {
    function transportButtons(state, paused) {
        var stopped = state === 'WaitingForLaunch' || state === 'Shutdown';
        return {
            pause: !stopped && !paused,
            resume: !!paused,
            stop: !stopped,
            start: state === 'WaitingForLaunch'
        };
    }

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = transportButtons;
    } else {
        root.transportButtons = transportButtons;
    }
})(typeof window !== 'undefined' ? window : this);
