package com.group2.crypto;

import com.group2.crypto.model.*;
import com.group2.crypto.service.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class CryptoLogicTest {

    @Test
    public void testAes() {
        AesService aes = new AesService();
        AesRequest req = new AesRequest();
        // Standard test vector
        req.setData("0123456789abcdeffedcba9876543210");
        req.setKey("0f1571c947d9e8590cb7add6af7f6798");
        req.setMode("encrypt");

        AesResponse res = aes.process(req);
        if (res.getErrorMessage() != null) System.out.println("AES Error: " + res.getErrorMessage());
        assertEquals("FF0B844A0853BF7C6934AB4364148FB9", res.getResult().toUpperCase());
        
        req.setData(res.getResult());
        req.setMode("decrypt");
        res = aes.process(req);
        assertEquals("0123456789ABCDEFFEDCBA9876543210", res.getResult().toUpperCase());
    }

    @Test
    public void testDes() {
        DesService des = new DesService();
        DesRequest req = new DesRequest();
        // Standard test vector
        req.setData("0123456789ABCDEF");
        req.setKey("133457799BBCDFF1");
        req.setMode("encrypt");

        DesResponse res = des.process(req);
        assertEquals("85E813540F0AB405", res.getResult().toUpperCase());

        req.setData(res.getResult());
        req.setMode("decrypt");
        res = des.process(req);
        assertEquals("0123456789ABCDEF", res.getResult().toUpperCase());
    }

    @Test
    public void testModuloMathReduction() {
        ModuloMathService moduloService = new ModuloMathService();
        MathModuloRequest req = new MathModuloRequest();
        req.setOperation("POWER");
        req.setSubMethod("REDUCTION");
        req.setA("3");
        req.setM("13");
        req.setN("7");

        MathModuloResponse res = moduloService.process(req);
        assertNull(res.getErrorMessage());
        assertEquals("3", res.getResult());
        
        // Assert transcript has binary decomposition and intermediate steps
        assertNotNull(res.getTranscript());
        assertTrue(res.getTranscript().stream().anyMatch(line -> line.contains("13 = 8 + 4 + 1")));
    }

    @Test
    public void testAesExamRoundOps() {
        AesService aes = new AesService();
        AesRequest req = new AesRequest();
        req.setOpType("EXAM_ROUND_OPS");
        req.setData("589D36EBFDEE387D0FCC9BED4C4046BD");
        req.setRoundNum(5);

        AesResponse res = aes.process(req);
        assertNull(res.getErrorMessage());
        assertNotNull(res.getResult());
        
        assertNotNull(res.getTranscript());
        assertTrue(res.getTranscript().stream().anyMatch(line -> line.contains("Giá trị tại vị trí này là: C6")));
    }

    @Test
    public void testAesExamRoundOpsRound10() {
        AesService aes = new AesService();
        AesRequest req = new AesRequest();
        req.setOpType("EXAM_ROUND_OPS");
        req.setData("589D36EBFDEE387D0FCC9BED4C4046BD");
        req.setRoundNum(10);

        AesResponse res = aes.process(req);
        assertNull(res.getErrorMessage());
        assertEquals("6A28147A544B5AE9760905FF295E0755", res.getResult());
        
        assertNotNull(res.getTranscript());
        assertTrue(res.getTranscript().stream().anyMatch(line -> line.contains("Vì vòng lặp thứ 10 là vòng lặp cuối cùng của AES-128, thuật toán không thực hiện phép trộn cột (MixColumns).")));
        assertTrue(res.getTranscript().stream().anyMatch(line -> line.contains("Giá trị tại vị trí này là: 54")));
    }

    @Test
    public void testAesExamKeyExp() {
        AesService aes = new AesService();
        AesRequest req = new AesRequest();
        req.setOpType("EXAM_KEY_EXP");
        req.setKey("0F1571C947D9E8590CB7ADD6AF7F6798");
        req.setRoundNum(3);

        AesResponse res = aes.process(req);
        assertNull(res.getErrorMessage());
        assertEquals("D99037B09E49DFE992FE723F3D8115A7", res.getResult());
        
        assertNotNull(res.getTranscript());
        assertTrue(res.getTranscript().stream().anyMatch(line -> line.contains("RotWord(AF7F6798) = 7F6798AF")));
        assertTrue(res.getTranscript().stream().anyMatch(line -> line.contains("SubWord(7F6798AF) = D2854679")));
        assertTrue(res.getTranscript().stream().anyMatch(line -> line.contains("xrc = s ⊕ Rcon[3] = D2854679 ⊕ 04000000 = D6854679")));
    }

    @Test
    public void testDesExamFeistel() {
        DesService des = new DesService();
        DesRequest req = new DesRequest();
        req.setOpType("EXAM_FEISTEL");
        req.setData("C11BFC09");
        req.setKey("710DEAA3202B");
        req.setRoundNum(1);

        DesResponse res = des.process(req);
        assertNull(res.getErrorMessage());
        assertEquals("E7CEA2DF", res.getResult());
        
        assertNotNull(res.getTranscript());
        assertTrue(res.getTranscript().stream().anyMatch(line -> line.contains("111000000010100011110111111111111000000001010011")));
        assertTrue(res.getTranscript().stream().anyMatch(line -> line.contains("91251D5CA078")));
        assertTrue(res.getTranscript().stream().anyMatch(line -> line.contains("E7CEA2DF")));
    }
}
