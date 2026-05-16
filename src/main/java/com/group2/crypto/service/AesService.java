package com.group2.crypto.service;

import com.group2.crypto.model.AesRequest;
import com.group2.crypto.model.AesResponse;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

@Service
public class AesService {

    private static final byte[] SBOX = {
            (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5,
            (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76,
            (byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0,
            (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0,
            (byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc,
            (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15,
            (byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a,
            (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75,
            (byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0,
            (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84,
            (byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b,
            (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf,
            (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85,
            (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8,
            (byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5,
            (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2,
            (byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17,
            (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73,
            (byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88,
            (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb,
            (byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c,
            (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79,
            (byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9,
            (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08,
            (byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6,
            (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a,
            (byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e,
            (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e,
            (byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94,
            (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf,
            (byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68,
            (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16
    };

    private static final int[] RCON = {
            0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000,
            0x36000000
    };

    public AesResponse process(AesRequest request) {
        AesResponse response = new AesResponse();
        response.setInputData(request.getData());
        response.setInputKey(request.getKey());
        response.setMode(request.getMode());

        try {
            String cleanData = request.getData().replaceAll("\\s+", "");
            String cleanKey = request.getKey().replaceAll("\\s+", "");
            byte[] data = HexFormat.of().parseHex(cleanData);
            byte[] key = HexFormat.of().parseHex(cleanKey);

            if (data.length != 16 || key.length != 16) {
                response.setErrorMessage("Dữ liệu và khóa phải đủ 128-bit (32 ký tự hex).");
                return response;
            }

            List<String> transcript = new ArrayList<>();
            transcript.add("BÀI TẬP MÃ HÓA AES - TRÍCH XUẤT");
            transcript.add("INPUT: K = " + cleanKey.toUpperCase() + ", M = " + cleanData.toUpperCase());
            transcript.add("");
            transcript.add("Phần 1: Sinh các khóa Ki từ khóa K");
            transcript.add("Bài 1: Tính các khóa vòng K1 đến K10 (Key Expansion)");

            byte[][][] roundKeys = KeyExpansion(key, transcript);

            transcript.add("");
            transcript.add("Phần 2: Mã hóa");

            byte[] result;
            if ("encrypt".equalsIgnoreCase(request.getMode())) {
                result = AES(data, roundKeys, transcript);
            } else {
                result = decrypt(data, roundKeys, transcript);
            }

            response.setResult(HexFormat.of().formatHex(result).toUpperCase());
            response.setTranscript(transcript);

        } catch (IllegalArgumentException e) {
            response.setErrorMessage("Lỗi: Định dạng Hex không hợp lệ (chỉ chứa 0-9, A-F).");
        } catch (Exception e) {
            response.setErrorMessage("Lỗi xử lý: " + e.getMessage());
        }

        return response;
    }

    private byte[][][] KeyExpansion(byte[] key, List<String> transcript) {
        int[] w = new int[44];
        byte[][][] roundKeys = new byte[11][4][4];

        // Initial 4 words
        for (int i = 0; i < 4; i++) {
            w[i] = ((key[4 * i] & 0xFF) << 24) | ((key[4 * i + 1] & 0xFF) << 16) | ((key[4 * i + 2] & 0xFF) << 8)
                    | (key[4 * i + 3] & 0xFF);
        }

        setRoundKey(roundKeys[0], w, 0);

        for (int round = 1; round <= 10; round++) {
            transcript.add("");
            transcript.add("• Tìm K" + round + ":");

            int i = round * 4;
            int temp = w[i - 1];

            transcript.add("1. Chia khóa K" + (round - 1) + " (128 bit) thành 4 word (32 bit)");
            transcript.add("   Input: K" + (round - 1) + " (input) = " + wordsToHex(w, i - 4, 4));
            transcript.add("   Output: " + String.format("w%d = %08X, w%d = %08X, w%d = %08X, w%d = %08X", i - 4,
                    w[i - 4], i - 3, w[i - 3], i - 2, w[i - 2], i - 1, w[i - 1]));

            // Step 2: RotWord
            int rw = rotWord(temp);
            transcript.add("2. Dịch vòng trái 1 byte đối với w" + (i - 1) + " (32 bit)");
            transcript.add("   Input: w" + (i - 1) + " = " + String.format("%08X", temp));
            transcript.add("   Output: rw_" + round + " = RotWord(w" + (i - 1) + ") = " + String.format("%08X", rw));

            // Step 3: SubWord
            int sw = subWord(rw);
            transcript.add("3. Thay thế từng byte trong rw_" + round + " bằng bảng S-box SubWord");
            transcript.add("   Input: rw_" + round + " = " + String.format("%08X", rw) + "; Sbox");
            transcript.add("   Output: sw_" + round + " = SubWord(rw_" + round + ") = " + String.format("%08X", sw));

            // Step 4: XOR with Rcon
            int rconVal = RCON[round - 1];
            int xcsw = sw ^ rconVal;
            transcript.add("4. sw_" + round + " XORbit với Rcon[" + round + "]");
            transcript.add("   Input: sw_" + round + " = " + String.format("%08X", sw) + "; RC[" + round + "] = "
                    + String.format("%08X", rconVal));
            transcript.add("   Output: xcsw_" + round + " = XorRcon(sw_" + round + ", RC[" + round + "]) = " + String.format("%08X", xcsw));

            // Step 5: Finalize round words
            transcript.add(
                    "5. Tính khóa K" + round + " = (w" + i + ", w" + (i + 1) + ", w" + (i + 2) + ", w" + (i + 3) + ")");
            transcript.add("   Input: xcsw_" + round + " = " + String.format("%08X", xcsw) + "; w" + (i - 4) + ", w" + (i - 3) + ", w"
                    + (i - 2) + ", w" + (i - 1));
            transcript.add("   Output:");

            w[i] = w[i - 4] ^ xcsw;
            transcript.add(
                    String.format("   w%d = XORbit(xcsw_%d, w%d) = %08X ⊕ %08X = %08X", i, round, i - 4, xcsw, w[i - 4], w[i]));

            w[i + 1] = w[i] ^ w[i - 3];
            transcript.add(String.format("   w%d = XORbit(w%d, w%d) = %08X ⊕ %08X = %08X", i + 1, i, i - 3, w[i],
                    w[i - 3], w[i + 1]));

            w[i + 2] = w[i + 1] ^ w[i - 2];
            transcript.add(String.format("   w%d = XORbit(w%d, w%d) = %08X ⊕ %08X = %08X", i + 2, i + 1, i - 2,
                    w[i + 1], w[i - 2], w[i + 2]));

            w[i + 3] = w[i + 2] ^ w[i - 1];
            transcript.add(String.format("   w%d = XORbit(w%d, w%d) = %08X ⊕ %08X = %08X", i + 3, i + 2, i - 1,
                    w[i + 2], w[i - 1], w[i + 3]));

            transcript.add("   => K" + round + ": " + wordsToHex(w, i, 4));

            setRoundKey(roundKeys[round], w, i);
        }

        return roundKeys;
    }

    private byte[] AES(byte[] plaintext, byte[][][] roundKeys, List<String> transcript) {
        byte[][] state = bytesToState(plaintext);

        transcript.add("");
        transcript.add("Bài 2: Khởi tạo (AddRoundKey với K0)");
        transcript.add("   M (input) = " + stateToHex(state) + " (16)");
        transcript.add("   K0 (input) = " + stateToHex(roundKeys[0]) + " (16)");
        ADDROUNDKEY(state, roundKeys[0]);
        transcript.add("   State_0 = M xor K0 = " + stateToHex(state) + " (16)");

        for (int round = 1; round <= 10; round++) {
            transcript.add("");
            transcript.add("Chi tiết vòng lặp " + round + ":");

            transcript.add("Bài 3: Thực hiện phép thế S-box (SubBytes) đối với State_" + (round - 1));
            transcript.add("   Input: State_" + (round - 1) + " = " + stateToHex(state) + " (16)");
            for (int c = 0; c < 4; c++) {
                for (int r = 0; r < 4; r++) {
                    byte b = state[r][c];
                    int idx = b & 0xFF;
                    int row = (idx >>> 4) & 0x0F;
                    int col = idx & 0x0F;
                    byte val = SBOX[idx];
                    state[r][c] = val;
                    transcript.add(String.format("   S%d(%02X) -> [%d] [%d] -> %d (%02X)", (c * 4 + r + 1), idx, row, col, val & 0xFF, val & 0xFF));
                }
            }
            transcript.add("   Sub_" + round + " = SUB(State_" + (round - 1) + ") = " + stateToHex(state) + " (16)");

            transcript.add("Bài 4: Thực hiện phép dịch vòng (ShiftRows) đối với Sub_" + round);
            transcript.add("   Input: Sub_" + round + " = " + stateToHex(state) + " (16)");
            for(int r = 0; r < 4; r++) {
                String before = String.format("[%02X, %02X, %02X, %02X]", state[r][0]&0xFF, state[r][1]&0xFF, state[r][2]&0xFF, state[r][3]&0xFF);
                byte[] row = new byte[4];
                for (int c = 0; c < 4; c++) row[c] = state[r][c];
                for (int c = 0; c < 4; c++) state[r][c] = row[(c + r) % 4];
                String after = String.format("[%02X, %02X, %02X, %02X]", state[r][0]&0xFF, state[r][1]&0xFF, state[r][2]&0xFF, state[r][3]&0xFF);
                
                String shiftName = (r == 0) ? "không dịch" : ("dịch trái " + r);
                transcript.add(String.format("   Hàng %d (%s): %s -> %s", r, shiftName, before, after));
            }
            transcript.add("   Shift_" + round + " = SHIFTROW(Sub_" + round + ") = " + stateToHex(state) + " (16)");

            if (round < 10) {
                transcript.add("Bài 5: Thực hiện phép trộn cột (MixColumns) đối với Shift_" + round);
                transcript.add("   Input: Shift_" + round + " = " + stateToHex(state) + " (16)");
                
                byte[][] tempState = new byte[4][4];
                for (int c = 0; c < 4; c++) {
                    byte b0 = state[0][c], b1 = state[1][c], b2 = state[2][c], b3 = state[3][c];
                    tempState[0][c] = (byte) (gm(2, b0) ^ gm(3, b1) ^ b2 ^ b3);
                    tempState[1][c] = (byte) (b0 ^ gm(2, b1) ^ gm(3, b2) ^ b3);
                    tempState[2][c] = (byte) (b0 ^ b1 ^ gm(2, b2) ^ gm(3, b3));
                    tempState[3][c] = (byte) (gm(3, b0) ^ b1 ^ b2 ^ gm(2, b3));
                    
                    transcript.add(String.format("   Cột %d:", c + 1));
                    transcript.add(String.format("     s'0 = 02*%02X ⊕ 03*%02X ⊕ 01*%02X ⊕ 01*%02X = %02X", b0&0xFF, b1&0xFF, b2&0xFF, b3&0xFF, tempState[0][c]&0xFF));
                    transcript.add(String.format("     s'1 = 01*%02X ⊕ 02*%02X ⊕ 03*%02X ⊕ 01*%02X = %02X", b0&0xFF, b1&0xFF, b2&0xFF, b3&0xFF, tempState[1][c]&0xFF));
                    transcript.add(String.format("     s'2 = 01*%02X ⊕ 01*%02X ⊕ 02*%02X ⊕ 03*%02X = %02X", b0&0xFF, b1&0xFF, b2&0xFF, b3&0xFF, tempState[2][c]&0xFF));
                    transcript.add(String.format("     s'3 = 03*%02X ⊕ 01*%02X ⊕ 01*%02X ⊕ 02*%02X = %02X", b0&0xFF, b1&0xFF, b2&0xFF, b3&0xFF, tempState[3][c]&0xFF));
                }
                
                for (int c = 0; c < 4; c++) {
                    for(int r = 0; r < 4; r++) {
                        state[r][c] = tempState[r][c];
                    }
                }
                
                transcript.add("   Mix_" + round + " = MIXCOLUMN(Shift_" + round + ") = " + stateToHex(state) + " (16)");
            } else {
                transcript.add("Bài 5: (Vòng cuối không có phép MixColumns)");
            }

            String prevVar = (round < 10) ? "Mix_" + round : "Shift_" + round;
            transcript.add("Bài 6: Thực hiện xor " + prevVar + " với khóa K" + round + " (AddRoundKey)");
            transcript.add("   K" + round + " = " + stateToHex(roundKeys[round]) + " (16)");
            transcript.add("   Input: " + prevVar + " = " + stateToHex(state) + " (16)");
            ADDROUNDKEY(state, roundKeys[round]);
            transcript.add("   State_" + round + " = " + prevVar + " xor K" + round + " = " + stateToHex(state) + " (16)");
        }

        transcript.add("");
        transcript.add("Bài 7: Kết quả bản mã");
        transcript.add("=> C = State_10 = " + stateToHex(state) + " (16)");

        return stateToBytes(state);
    }

    private byte[] decrypt(byte[] ciphertext, byte[][][] roundKeys, List<String> transcript) {
        byte[][] state = bytesToState(ciphertext);
        transcript.add("Bắt đầu giải mã...");
        ADDROUNDKEY(state, roundKeys[10]);
        for (int round = 9; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            ADDROUNDKEY(state, roundKeys[round]);
            invMixColumns(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        ADDROUNDKEY(state, roundKeys[0]);
        return stateToBytes(state);
    }

    private String wordsToHex(int[] w, int start, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append(String.format("%08X", w[start + i]));
        }
        return sb.toString();
    }

    private String stateToHex(byte[][] state) {
        byte[] bytes = stateToBytes(state);
        return HexFormat.of().formatHex(bytes).toUpperCase();
    }

    private void setRoundKey(byte[][] state, int[] w, int start) {
        for (int j = 0; j < 4; j++) {
            int word = w[start + j];
            state[0][j] = (byte) (word >>> 24);
            state[1][j] = (byte) (word >>> 16);
            state[2][j] = (byte) (word >>> 8);
            state[3][j] = (byte) word;
        }
    }

    private int rotWord(int w) {
        return (w << 8) | (w >>> 24);
    }

    private int subWord(int w) {
        return ((SBOX[(w >>> 24) & 0xFF] & 0xFF) << 24) |
                ((SBOX[(w >>> 16) & 0xFF] & 0xFF) << 16) |
                ((SBOX[(w >>> 8) & 0xFF] & 0xFF) << 8) |
                (SBOX[w & 0xFF] & 0xFF);
    }

    private void ADDROUNDKEY(byte[][] state, byte[][] roundKey) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] ^= roundKey[r][c];
    }

    private void SUBBYTE(byte[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = SBOX[state[r][c] & 0xFF];
    }

    private void invSubBytes(byte[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++) {
                byte b = state[r][c];
                for (int i = 0; i < 256; i++) {
                    if (SBOX[i] == b) {
                        state[r][c] = (byte) i;
                        break;
                    }
                }
            }
    }

    private void SHIFTROW(byte[][] state) {
        for (int r = 1; r < 4; r++) {
            byte[] row = new byte[4];
            for (int c = 0; c < 4; c++)
                row[c] = state[r][c];
            for (int c = 0; c < 4; c++)
                state[r][c] = row[(c + r) % 4];
        }
    }

    private void invShiftRows(byte[][] state) {
        for (int r = 1; r < 4; r++) {
            byte[] row = new byte[4];
            for (int c = 0; c < 4; c++)
                row[c] = state[r][c];
            for (int c = 0; c < 4; c++)
                state[r][c] = row[(c - r + 4) % 4];
        }
    }

    private void MIXCOLUMN(byte[][] state) {
        for (int c = 0; c < 4; c++) {
            byte b0 = state[0][c], b1 = state[1][c], b2 = state[2][c], b3 = state[3][c];
            state[0][c] = (byte) (gm(2, b0) ^ gm(3, b1) ^ b2 ^ b3);
            state[1][c] = (byte) (b0 ^ gm(2, b1) ^ gm(3, b2) ^ b3);
            state[2][c] = (byte) (b0 ^ b1 ^ gm(2, b2) ^ gm(3, b3));
            state[3][c] = (byte) (gm(3, b0) ^ b1 ^ b2 ^ gm(2, b3));
        }
    }

    private void invMixColumns(byte[][] state) {
        for (int c = 0; c < 4; c++) {
            byte b0 = state[0][c], b1 = state[1][c], b2 = state[2][c], b3 = state[3][c];
            state[0][c] = (byte) (gm(14, b0) ^ gm(11, b1) ^ gm(13, b2) ^ gm(9, b3));
            state[1][c] = (byte) (gm(9, b0) ^ gm(14, b1) ^ gm(11, b2) ^ gm(13, b3));
            state[2][c] = (byte) (gm(13, b0) ^ gm(9, b1) ^ gm(14, b2) ^ gm(11, b3));
            state[3][c] = (byte) (gm(11, b0) ^ gm(13, b1) ^ gm(9, b2) ^ gm(14, b3));
        }
    }

    private byte gm(int a, byte b) {
        int res = 0;
        int bb = b & 0xFF;
        for (int i = 0; i < 8; i++) {
            if ((a & 1) != 0)
                res ^= bb;
            int hi_bit = (bb & 0x80);
            bb <<= 1;
            if (hi_bit != 0)
                bb ^= 0x1B;
            bb &= 0xFF;
            a >>= 1;
        }
        return (byte) res;
    }

    private byte[][] bytesToState(byte[] bytes) {
        byte[][] state = new byte[4][4];
        for (int i = 0; i < 16; i++) {
            state[i % 4][i / 4] = bytes[i];
        }
        return state;
    }

    private byte[] stateToBytes(byte[][] state) {
        byte[] bytes = new byte[16];
        for (int i = 0; i < 16; i++) {
            bytes[i] = state[i % 4][i / 4];
        }
        return bytes;
    }
}
