package org.androidtrustlab.observer

import android.app.Activity
import android.os.Bundle

/** Entry point for the deliberately unprivileged observer application. */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
    }
}
