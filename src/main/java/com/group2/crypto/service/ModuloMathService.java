package com.group2.crypto.service;

import com.group2.crypto.model.MathModuloRequest;
import com.group2.crypto.model.MathModuloResponse;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

@Service
public class ModuloMathService {

    public MathModuloResponse process(MathModuloRequest request) {
        String op = request.getOperation().toUpperCase();
        switch (op) {
            case "POWER":
                return processPower(request);
            case "INVERSE":
                return processInverse(request);
            case "EULER":
                return processEuler(request);
            case "CRT_SYS":
                return processCRTSys(request);
            case "PR":
                return processPrimitiveRoot(request);
            case "LOG":
                return processDiscreteLog(request);
            case "BASIC":
                return processBasic(request);
            default:
                MathModuloResponse res = new MathModuloResponse();
                res.setErrorMessage("Thao tác không được hỗ trợ.");
                return res;
        }
    }

    private MathModuloResponse processPower(MathModuloRequest request) {
        String sub = request.getSubMethod().toUpperCase();
        if ("FERMAT".equals(sub)) return processFermat(request);
        if ("EULER".equals(sub)) {
            // Re-using Euler theorem part of processEuler
            return processEulerPower(request);
        }
        if ("CRT".equals(sub)) return processCRTExp(request);

        MathModuloResponse response = new MathModuloResponse();
        List<String> transcript = new ArrayList<>();
        try {
            BigInteger a = new BigInteger(request.getA());
            BigInteger m = new BigInteger(request.getM());
            BigInteger n = new BigInteger(request.getN());

            if (n.compareTo(BigInteger.ONE) <= 0) {
                response.setErrorMessage("Lỗi: n (mô-đun) phải lớn hơn 1.");
                return response;
            }

            transcript.add("TÍNH LŨY THỪA MODULO: " + a + "^" + m + " mod " + n);
            String mBin = m.toString(2);
            transcript.add("Bước 1: " + m + "(10) = " + mBin + "(2)");
            transcript.add("");
            transcript.add(String.format("%-5s | %-5s | %-15s | %-15s", "i", "bit", "Square", "Multiply"));
            transcript.add("---------------------------------------------------------");

            BigInteger f = BigInteger.ONE;
            for (int i = 0; i < mBin.length(); i++) {
                char bit = mBin.charAt(i);
                BigInteger prevF = f;
                f = f.multiply(f).mod(n);
                String sq = prevF + "^2 mod " + n + " = " + f;
                String mult = "-";
                if (bit == '1') {
                    prevF = f;
                    f = f.multiply(a).mod(n);
                    mult = prevF + "*" + a + " mod " + n + " = " + f;
                }
                transcript.add(String.format("%-5d | %-5c | %-15s | %-15s", i, bit, sq, mult));
            }
            response.setResult(f.toString());
            response.setTranscript(transcript);
        } catch (Exception e) {
            response.setErrorMessage("Lỗi tham số: " + e.getMessage());
        }
        return response;
    }

    private MathModuloResponse processFermat(MathModuloRequest request) {
        MathModuloResponse response = new MathModuloResponse();
        List<String> transcript = new ArrayList<>();
        try {
            BigInteger a = new BigInteger(request.getA());
            BigInteger m = new BigInteger(request.getM());
            BigInteger n = new BigInteger(request.getN());

            transcript.add("ĐỊNH LÝ FERMAT NHỎ: Tính " + a + "^" + m + " mod " + n);
            if (!n.isProbablePrime(10)) {
                response.setErrorMessage("Lỗi: n=" + n + " phải là số nguyên tố để áp dụng định lý Fermat nhỏ.");
                return response;
            }
            if (!a.gcd(n).equals(BigInteger.ONE)) {
                 response.setErrorMessage("Lỗi: gcd(a, n) = " + a.gcd(n) + " ≠ 1. Điều kiện áp dụng Fermat nhỏ là a và n phải nguyên tố cùng nhau.");
                 return response;
            }
            if (n.compareTo(BigInteger.ONE) <= 0) {
                response.setErrorMessage("Lỗi: n (mô-đun) phải lớn hơn 1.");
                return response;
            }

            BigInteger nMinus1 = n.subtract(BigInteger.ONE);
            BigInteger reducedExp = m.remainder(nMinus1);
            transcript.add("1. Kiểm tra điều kiện & Cơ sở lý thuyết:");
            transcript.add("Để áp dụng Định lý Fermat nhỏ, điều kiện bắt buộc là module n phải là số nguyên tố và a không chia hết cho n (tức gcd(a, n) = 1).");
            transcript.add("Ta có n = " + n + " là số nguyên tố và gcd(" + a + ", " + n + ") = 1 (thỏa mãn điều kiện).");
            transcript.add("Vậy ta có: " + a + "^" + nMinus1 + " ≡ 1 (mod " + n + ").");
            transcript.add("");
            transcript.add("2. Quá trình tính toán:");
            transcript.add("m' = m mod (n-1) = " + m + " mod " + nMinus1 + " = " + reducedExp);
            BigInteger res = a.modPow(reducedExp, n);
            transcript.add("Kết quả: " + a + "^" + reducedExp + " mod " + n + " = " + res);
            response.setResult(res.toString());
            response.setTranscript(transcript);
        } catch (Exception e) {
            response.setErrorMessage("Lỗi: " + e.getMessage());
        }
        return response;
    }

    private MathModuloResponse processEulerPower(MathModuloRequest request) {
        MathModuloResponse response = new MathModuloResponse();
        List<String> transcript = new ArrayList<>();
        try {
            BigInteger a = new BigInteger(request.getA());
            BigInteger m = new BigInteger(request.getM());
            BigInteger n = new BigInteger(request.getN());

            if (n.compareTo(BigInteger.ONE) <= 0) {
                response.setErrorMessage("Lỗi: n (mô-đun) phải lớn hơn 1.");
                return response;
            }

            if (!a.gcd(n).equals(BigInteger.ONE)) {
                 response.setErrorMessage("Lỗi: a=" + a + " và n=" + n + " không nguyên tố cùng nhau. Không thể áp dụng trực tiếp định lý Euler.");
                 return response;
            }

            BigInteger phi = getPhi(n);
            transcript.add("ỨNG DỤNG ĐỊNH LÝ EULER: Tính " + a + "^" + m + " mod " + n);
            transcript.add("1. Kiểm tra điều kiện & Cơ sở lý thuyết:");
            transcript.add("Định lý Euler là dạng tổng quát của Fermat nhỏ. Điều kiện để áp dụng là cơ số a và module n phải nguyên tố cùng nhau.");
            if (a.gcd(n).equals(BigInteger.ONE)) {
                transcript.add("Ta có gcd(a, n) = gcd(" + a + ", " + n + ") = 1 (thỏa mãn điều kiện).");
                transcript.add("Vậy ta có: " + a + "^Φ(" + n + ") ≡ 1 (mod " + n + ").");
                transcript.add("");
                transcript.add("2. Quá trình tính toán:");
                transcript.add("Tính Φ(" + n + ") = " + phi);
                BigInteger mPrime = m.remainder(phi);
                BigInteger res = a.modPow(mPrime, n);
                transcript.add("m' = " + m + " mod Φ(n) = " + m + " mod " + phi + " = " + mPrime);
                transcript.add("Kết quả: " + a + "^" + mPrime + " mod " + n + " = " + res);
                response.setResult(res.toString());
            } else {
                transcript.add("Lưu ý: gcd(" + a + "," + n + ") != 1. Không áp dụng trực tiếp Euler.");
                BigInteger res = a.modPow(m, n);
                response.setResult(res.toString());
            }
            response.setTranscript(transcript);
        } catch (Exception e) {
            response.setErrorMessage("Lỗi: " + e.getMessage());
        }
        return response;
    }

    private MathModuloResponse processInverse(MathModuloRequest request) {
        MathModuloResponse response = new MathModuloResponse();
        List<String> transcript = new ArrayList<>();
        try {
            BigInteger a = new BigInteger(request.getA().trim());
            BigInteger n = new BigInteger(request.getN().trim());
            String method = request.getSubMethod().toUpperCase();

            transcript.add("TÌM NGHỊCH ĐẢO MODULO: " + a + "^-1 mod " + n);
            
            if (n.compareTo(BigInteger.ONE) <= 0) {
                response.setErrorMessage("n phải lớn hơn 1.");
                return response;
            }

            BigInteger gcdVal = a.gcd(n);
            if (!gcdVal.equals(BigInteger.ONE)) {
                transcript.add("gcd(" + a + ", " + n + ") = " + gcdVal + " ≠ 1");
                transcript.add("=> Không tồn tại nghịch đảo modulo.");
                response.setResult("NONE");
            } else {
                if ("BRUTE".equalsIgnoreCase(method)) {
                    transcript.add("Phương pháp: Theo định nghĩa (Vét cạn)");
                    transcript.add("1. Kiểm tra điều kiện:");
                    transcript.add("gcd(" + a + ", " + n + ") = 1 => Tồn tại nghịch đảo x = a^-1 (mod n).");
                    transcript.add("");
                    transcript.add("2. Quá trình tính toán:");
                    transcript.add("Tìm x sao cho (" + a + " * x) mod " + n + " = 1");
                    for (long x = 1; x < n.longValue(); x++) {
                        BigInteger val = a.multiply(BigInteger.valueOf(x)).mod(n);
                        transcript.add(String.format("   x=%d: (%d * %d) mod %d = %d", x, a, x, n, val));
                        if (val.equals(BigInteger.ONE)) {
                            transcript.add("=> Tìm thấy x=" + x);
                            response.setResult(String.valueOf(x));
                            break;
                        }
                    }
                } else {
                    transcript.add("Phương pháp: Thuật toán Euclid mở rộng");
                    transcript.add("1. Kiểm tra điều kiện & Cơ sở lý thuyết:");
                    transcript.add("Để phần tử a có nghịch đảo theo modulo n, điều kiện bắt buộc là ước chung lớn nhất của chúng phải bằng 1.");
                    transcript.add("Ta thấy gcd(a, n) = gcd(" + a + ", " + n + ") = 1. Do đó, tồn tại nghịch đảo x = a^-1 (mod n). Áp dụng thuật toán Euclid mở rộng...");
                    transcript.add("");
                    transcript.add("2. Quá trình tính toán:");
                    transcript.add("Lập bảng tìm x sao cho ax + ny = 1 (mod n)");
                    transcript.add(String.format("%-7s | %-7s | %-10s | %-10s", "q", "r", "x", "y"));
                    transcript.add("--------------------------------------------");
                    
                    BigInteger r1 = n, r2 = a;
                    BigInteger x1 = BigInteger.ZERO, x2 = BigInteger.ONE;
                    BigInteger y1 = BigInteger.ONE, y2 = BigInteger.ZERO;
                    
                    transcript.add(String.format("%-7s | %-7s | %-10s | %-10s", "-", r1, x1, y1));
                    transcript.add(String.format("%-7s | %-7s | %-10s | %-10s", "-", r2, x2, y2));

                    while (r2.compareTo(BigInteger.ZERO) > 0) {
                        BigInteger q = r1.divide(r2);
                        BigInteger r = r1.remainder(r2);
                        BigInteger x = x1.subtract(q.multiply(x2));
                        BigInteger y = y1.subtract(q.multiply(y2));
                        
                        transcript.add(String.format("%-7s | %-7s | %-10s | %-10s", q, r, x, y));
                        
                        r1 = r2;
                        r2 = r;
                        x1 = x2;
                        x2 = x;
                        y1 = y2;
                        y2 = y;
                    }
                    
                    BigInteger inv = x1.remainder(n);
                    if (inv.compareTo(BigInteger.ZERO) < 0) inv = inv.add(n);
                    
                    transcript.add("");
                    transcript.add("=> x = " + x1 + " ≡ " + inv + " (mod " + n + ")");
                    response.setResult(inv.toString());
                }
            }
            response.setTranscript(transcript);
        } catch (Exception e) {
            response.setErrorMessage("Lỗi: " + e.getMessage());
        }
        return response;
    }

    private MathModuloResponse processEuler(MathModuloRequest request) {
        MathModuloResponse response = new MathModuloResponse();
        List<String> transcript = new ArrayList<>();
        try {
            BigInteger n = new BigInteger(request.getN());
            transcript.add("TÍNH HÀM PHI EULER Φ(" + n + ")");
            
            BigInteger phi = n;
            BigInteger d = BigInteger.valueOf(2);
            BigInteger tempN = n;
            List<BigInteger> factors = new ArrayList<>();
            while (d.multiply(d).compareTo(tempN) <= 0) {
                if (tempN.remainder(d).equals(BigInteger.ZERO)) {
                    factors.add(d);
                    phi = phi.divide(d).multiply(d.subtract(BigInteger.ONE));
                    while (tempN.remainder(d).equals(BigInteger.ZERO)) tempN = tempN.divide(d);
                }
                d = d.add(BigInteger.ONE);
            }
            if (tempN.compareTo(BigInteger.ONE) > 0) {
                factors.add(tempN);
                phi = phi.divide(tempN).multiply(tempN.subtract(BigInteger.ONE));
            }
            
            transcript.add("Các ước nguyên tố của " + n + ": " + factors);
            transcript.add("Công thức: Φ(n) = n * Π(1 - 1/p)");
            transcript.add("=> Φ(" + n + ") = " + phi);
            response.setResult(phi.toString());

            if (!request.getA().isEmpty() && !request.getM().isEmpty()) {
                BigInteger a = new BigInteger(request.getA());
                BigInteger m = new BigInteger(request.getM());
                transcript.add("");
                transcript.add("Ứng dụng định lý Euler: Tính " + a + "^" + m + " mod " + n);
                if (a.gcd(n).equals(BigInteger.ONE)) {
                    BigInteger mPrime = m.remainder(phi);
                    BigInteger res = a.modPow(mPrime, n);
                    transcript.add("Vì gcd(" + a + "," + n + ")=1 nên a^Φ(n) ≡ 1 (mod n)");
                    transcript.add("m' = " + m + " mod " + phi + " = " + mPrime);
                    transcript.add("Kết quả: " + res);
                } else {
                    transcript.add("gcd(" + a + "," + n + ") != 1. Không áp dụng được Euler.");
                }
            }
            response.setTranscript(transcript);
        } catch (Exception e) {
            response.setErrorMessage("Lỗi: " + e.getMessage());
        }
        return response;
    }

    private MathModuloResponse processCRTExp(MathModuloRequest request) {
        MathModuloResponse response = new MathModuloResponse();
        List<String> transcript = new ArrayList<>();
        try {
            BigInteger a = new BigInteger(request.getA());
            BigInteger k = new BigInteger(request.getM());
            BigInteger n = new BigInteger(request.getN());
            // In report example: n = 43381 = 13 * 47 * 71
            transcript.add("SỬ DỤNG CRT ĐỂ TÍNH LŨY THỪA: " + a + "^" + k + " mod " + n);
            
            // For simplicity, we assume the user knows the factors for now or we could factor (but only for small n)
            // Report shows n factors. Let's try to factor n.
            List<BigInteger> m = getPrimeFactors(n);
            transcript.add("1. Kiểm tra điều kiện & Cơ sở lý thuyết:");
            transcript.add("Để tính lũy thừa bằng CRT, ta phân tích n = " + n + " thành các thừa số nguyên tố cùng nhau: " + m);
            transcript.add("Điều kiện bắt buộc là các module thành phần phải nguyên tố cùng nhau từng đôi một (pairwise coprime).");
            transcript.add("Các thừa số " + m + " thỏa mãn điều kiện. Áp dụng định lý CRT...");
            transcript.add("");
            transcript.add("2. Quá trình tính toán:");
            
            BigInteger[] a_i = new BigInteger[m.size()];
            for (int i = 0; i < m.size(); i++) {
                a_i[i] = a.modPow(k, m.get(i));
                transcript.add(String.format("   a%d = %s^%s mod %s = %s", i+1, a, k, m.get(i), a_i[i]));
            }
            
            BigInteger res = solveCRT(a_i, m.toArray(new BigInteger[0]));
            transcript.add("2. Giải hệ bằng CRT => b = " + res);
            response.setResult(res.toString());
            response.setTranscript(transcript);
        } catch (Exception e) {
            response.setErrorMessage("Lỗi: " + e.getMessage());
        }
        return response;
    }

    private MathModuloResponse processCRTSys(MathModuloRequest request) {
        MathModuloResponse response = new MathModuloResponse();
        List<String> transcript = new ArrayList<>();
        try {
            String sys = request.getSystem();
            String[] pairs = sys.split(";");
            BigInteger[] a = new BigInteger[pairs.length];
            BigInteger[] m = new BigInteger[pairs.length];
            
            transcript.add("GIẢI HỆ PHƯƠNG TRÌNH ĐỊNH LÝ SỐ DƯ TRUNG HOA (CRT)");
            BigInteger M = BigInteger.ONE;
            StringBuilder mStrList = new StringBuilder();
            boolean pairwiseCoprime = true;
            for (int i = 0; i < pairs.length; i++) {
                String[] parts = pairs[i].split(",");
                a[i] = new BigInteger(parts[0].trim());
                m[i] = new BigInteger(parts[1].trim());
                M = M.multiply(m[i]);
                mStrList.append(m[i]).append(i == pairs.length - 1 ? "" : ", ");
                transcript.add(String.format("   PT%d: x ≡ %s (mod %s)", i+1, a[i], m[i]));
            }
            
            for (int i = 0; i < m.length; i++) {
                for (int j = i + 1; j < m.length; j++) {
                    if (!m[i].gcd(m[j]).equals(BigInteger.ONE)) pairwiseCoprime = false;
                }
            }
            
            transcript.add("");
            transcript.add("1. Kiểm tra điều kiện & Cơ sở lý thuyết:");
            transcript.add("Để hệ phương trình modulo có nghiệm duy nhất theo Định lý Số dư Trung Hoa, điều kiện bắt buộc là các module m_1, m_2, ... phải nguyên tố cùng nhau từng đôi một (pairwise coprime).");
            if (pairwiseCoprime) {
                transcript.add("Xét các module " + mStrList.toString() + ", ta thấy gcd(m_i, m_j) = 1 (thỏa mãn điều kiện). Áp dụng định lý CRT...");
            } else {
                 response.setErrorMessage("Lỗi: Các module không nguyên tố cùng nhau từng đôi một. Không thể áp dụng trực tiếp CRT.");
                 return response;
            }
            transcript.add("");
            transcript.add("2. Quá trình tính toán:");
            transcript.add("Tính M = m1*m2*...*mk = " + M);
            
            BigInteger result = BigInteger.ZERO;
            transcript.add(String.format("%-5s | %-15s | %-15s | %-15s", "i", "Mi = M/mi", "yi = Mi^-1 mod mi", "Mi*yi*ai"));
            transcript.add("------------------------------------------------------------------");
            
            for (int i = 0; i < a.length; i++) {
                BigInteger Mi = M.divide(m[i]);
                BigInteger yi = Mi.modInverse(m[i]);
                BigInteger term = Mi.multiply(yi).multiply(a[i]);
                result = result.add(term);
                transcript.add(String.format("%-5d | %-15s | %-15s | %-15s", i+1, Mi, yi, term));
            }
            
            BigInteger finalX = result.mod(M);
            transcript.add("");
            transcript.add("2. Tính x = Σ(Mi * yi * ai) mod M");
            transcript.add("=> x = " + result + " mod " + M + " = " + finalX);
            
            response.setResult(finalX.toString());
            response.setTranscript(transcript);
        } catch (Exception e) {
            response.setErrorMessage("Lỗi: Định dạng sai hoặc các modulo không nguyên tố cùng nhau.");
        }
        return response;
    }

    private MathModuloResponse processPrimitiveRoot(MathModuloRequest request) {
        MathModuloResponse response = new MathModuloResponse();
        List<String> transcript = new ArrayList<>();
        try {
            BigInteger a = new BigInteger(request.getA());
            BigInteger n = new BigInteger(request.getN());
            
            if (n.compareTo(BigInteger.ONE) <= 0) {
                response.setErrorMessage("Lỗi: n (mô-đun) phải lớn hơn 1.");
                return response;
            }
            if (!a.gcd(n).equals(BigInteger.ONE)) {
                response.setErrorMessage("Lỗi: a=" + a + " và n=" + n + " không nguyên tố cùng nhau. Căn nguyên thủy a phải nguyên tố cùng nhau với n.");
                return response;
            }

            transcript.add("KIỂM TRA CĂN NGUYÊN THỦY: a=" + a + ", n=" + n);
            
            BigInteger phi = getPhi(n);
            transcript.add("1. Φ(n) = " + phi);
            List<BigInteger> factors = getPrimeFactors(phi);
            transcript.add("2. Các ước nguyên tố của Φ(n): " + factors);
            
            boolean isPR = true;
            for (BigInteger p : factors) {
                BigInteger exp = phi.divide(p);
                BigInteger res = a.modPow(exp, n);
                transcript.add(String.format("   %s^(%s/%s) mod %s = %s", a, phi, p, n, res));
                if (res.equals(BigInteger.ONE)) {
                    isPR = false;
                    break;
                }
            }
            
            if (isPR) {
                response.setResult("YES");
                transcript.add("=> " + a + " LÀ căn nguyên thủy của " + n);
            } else {
                response.setResult("NO");
                transcript.add("=> " + a + " KHÔNG PHẢI căn nguyên thủy.");
            }
            response.setTranscript(transcript);
        } catch (Exception e) {
            response.setErrorMessage("Lỗi: " + e.getMessage());
        }
        return response;
    }

    private MathModuloResponse processDiscreteLog(MathModuloRequest request) {
        MathModuloResponse response = new MathModuloResponse();
        List<String> transcript = new ArrayList<>();
        try {
            BigInteger a = new BigInteger(request.getA().trim());
            BigInteger b = new BigInteger(request.getB().trim());
            BigInteger n = new BigInteger(request.getN().trim());
            transcript.add("TÌM LOGARITHM RỜI RẠC: " + a + "^k ≡ " + b + " mod " + n);

            BigInteger phi = getPhi(n);
            transcript.add("Duyệt k từ 1 đến Φ(n) = " + phi + ":");
            long kFound = -1;
            for (long k = 1; k <= phi.longValue(); k++) {
                BigInteger val = a.modPow(BigInteger.valueOf(k), n);
                transcript.add(String.format("   k=%d: %d^%d mod %d = %d", k, a, k, n, val));
                if (val.equals(b)) {
                    kFound = k;
                    break;
                }
            }

            if (kFound != -1) {
                response.setResult(String.valueOf(kFound));
                transcript.add("=> Kết quả k = " + kFound);
            } else {
                response.setResult("NOT FOUND");
                transcript.add("=> Không tìm thấy k thỏa mãn.");
            }
            response.setTranscript(transcript);
        } catch (Exception e) {
            response.setErrorMessage("Lỗi tham số: " + e.getMessage());
        }
        return response;
    }

    private MathModuloResponse processBasic(MathModuloRequest request) {
        MathModuloResponse response = new MathModuloResponse();
        List<String> transcript = new ArrayList<>();
        try {
            BigInteger a = new BigInteger(request.getA().trim());
            BigInteger b = new BigInteger(request.getB().trim());
            BigInteger x = new BigInteger(request.getM().trim());
            BigInteger y = new BigInteger(request.getY().trim());
            BigInteger n = new BigInteger(request.getN().trim());
            
            if (n.compareTo(BigInteger.ONE) <= 0) {
                response.setErrorMessage("Lỗi: n (mô-đun) phải lớn hơn 1.");
                return response;
            }
            
            BigInteger ax = a.modPow(x, n);
            BigInteger by = b.modPow(y, n);
            
            transcript.add("TÍNH BIỂU THỨC MODULO CƠ BẢN (A1-A5)");
            transcript.add("Tham số: a=" + a + ", b=" + b + ", x=" + x + ", y=" + y + ", n=" + n);
            transcript.add("");
            transcript.add("1. a^x mod n = " + a + "^" + x + " mod " + n + " = " + ax);
            transcript.add("2. b^y mod n = " + b + "^" + y + " mod " + n + " = " + by);
            
            BigInteger a1 = ax.add(by).mod(n);
            BigInteger a2 = ax.subtract(by).mod(n);
            if (a2.compareTo(BigInteger.ZERO) < 0) a2 = a2.add(n);
            BigInteger a3 = ax.multiply(by).mod(n);
            
            transcript.add("A1 = (a^x + b^y) mod n = " + a1);
            transcript.add("A2 = (a^x - b^y) mod n = " + a2);
            transcript.add("A3 = (a^x * b^y) mod n = " + a3);
            
            try {
                BigInteger invBy = by.modInverse(n);
                transcript.add("A4 = (b^y)^-1 mod n = " + invBy);
                transcript.add("A5 = (a^x / b^y) mod n = " + ax.multiply(invBy).mod(n));
            } catch (Exception e) {
                transcript.add("A4, A5: Không tồn tại nghịch đảo cho b^y mod n.");
            }
            
            response.setResult("A1=" + a1 + ", A2=" + a2 + ", A3=" + a3);
            response.setTranscript(transcript);
        } catch (Exception e) {
            response.setErrorMessage("Lỗi: " + e.getMessage());
        }
        return response;
    }

    // Helper methods
    private List<BigInteger> getPrimeFactors(BigInteger n) {
        List<BigInteger> factors = new ArrayList<>();
        BigInteger d = BigInteger.valueOf(2);
        BigInteger tempN = n;
        while (d.multiply(d).compareTo(tempN) <= 0) {
            if (tempN.remainder(d).equals(BigInteger.ZERO)) {
                factors.add(d);
                while (tempN.remainder(d).equals(BigInteger.ZERO)) tempN = tempN.divide(d);
            }
            d = d.add(BigInteger.ONE);
        }
        if (tempN.compareTo(BigInteger.ONE) > 0) factors.add(tempN);
        return factors;
    }

    private BigInteger getPhi(BigInteger n) {
        BigInteger phi = n;
        for (BigInteger p : getPrimeFactors(n)) {
            phi = phi.divide(p).multiply(p.subtract(BigInteger.ONE));
        }
        return phi;
    }

    private BigInteger solveCRT(BigInteger[] a, BigInteger[] m) {
        BigInteger M = BigInteger.ONE;
        for (BigInteger mod : m) M = M.multiply(mod);
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < a.length; i++) {
            BigInteger Mi = M.divide(m[i]);
            BigInteger yi = Mi.modInverse(m[i]);
            result = result.add(a[i].multiply(Mi).multiply(yi));
        }
        return result.mod(M);
    }
}
