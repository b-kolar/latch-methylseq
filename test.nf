workflow {
    _latch_placeholder_log = Channel.of(1,2,3)

    emit:
        _latch_placeholder_log
}
