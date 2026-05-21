package com.group2.crypto.model;


public class MathModuloRequest {
    private String operation = "POWER"; 
    private String subMethod = "BASIC"; // For POWER: BASIC | REDUCTION | FERMAT | EULER | CRT
    private String a = "";
    private String m = "";
    private String n = "";
    private String b = "";     // For discrete log or CRT systems
    private String y = "";     // For basic expressions
    private String system = ""; // For CRT system input format: "a1,m1; a2,m2; ..."

    // Getters and Setters
    public String getOperation() { return operation; }
    public void setOperation(String operation) { this.operation = operation; }
    public String getSubMethod() { return subMethod; }
    public void setSubMethod(String subMethod) { this.subMethod = subMethod; }
    public String getA() { return a; }
    public void setA(String a) { this.a = a; }
    public String getM() { return m; }
    public void setM(String m) { this.m = m; }
    public String getN() { return n; }
    public void setN(String n) { this.n = n; }
    public String getB() { return b; }
    public void setB(String b) { this.b = b; }
    public String getY() { return y; }
    public void setY(String y) { this.y = y; }
    public String getSystem() { return system; }
    public void setSystem(String system) { this.system = system; }
}
