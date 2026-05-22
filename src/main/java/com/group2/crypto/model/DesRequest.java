package com.group2.crypto.model;

public class DesRequest {
    private String data = "";
    private String key = "";
    private String mode = "encrypt"; // encrypt or decrypt
    private String stepMode = "FULL"; // FULL or SINGLE
    private String opType = "FULL";   // FULL or EXAM_FEISTEL
    private int roundNum = 1;

    public String getData() { return data; }
    public void setData(String data) { this.data = data; }
    public String getKey() { return key; }
    public void setKey(String key) { this.key = key; }
    public String getMode() { return mode; }
    public void setMode(String mode) { this.mode = mode; }
    public String getStepMode() { return stepMode; }
    public void setStepMode(String stepMode) { this.stepMode = stepMode; }
    public String getOpType() { return opType; }
    public void setOpType(String opType) { this.opType = opType; }
    public int getRoundNum() { return roundNum; }
    public void setRoundNum(int roundNum) { this.roundNum = roundNum; }
}
