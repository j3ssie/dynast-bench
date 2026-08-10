package com.bench.springboot;

import java.nio.charset.StandardCharsets;

// A deserialization "gadget": a class whose setter has a side effect. It stands
// in for the real classpath gadgets that make Jackson polymorphic deserialization
// an RCE. Present in BOTH variants - it is only ever weaponised when an endpoint
// enables default typing and lets attacker JSON name it (see JACKSON-DESER-001).
public class GadgetProbe {
    private String output = "";
    public String getOutput() { return output; }
    public void setCommand(String command) {
        try {
            Process p = new ProcessBuilder("sh", "-c", command).redirectErrorStream(true).start();
            this.output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            this.output = "err:" + e.getMessage();
        }
    }
    @Override public String toString() { return output; }
}
