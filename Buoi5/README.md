# BÁO CÁO THỰC HÀNH BUỔI 5: PHÁT TRIỂN CÔNG CỤ SAST VÀ DAST
**Môn học:** Thực hành Lập trình An toàn Thông tin (TH LTANTT)  
**Chủ đề:** Static Application Security Testing (SAST) & Dynamic Application Security Testing (DAST)  

---

## MỤC LỤC
1. [Tổng quan](#1-tổng-quan)
2. [Cấu trúc thư mục dự án](#2-cấu-trúc-thư-mục-dự-án)
3. [Lab 1: Công cụ kiểm thử bảo mật tĩnh (SAST Tool)](#3-lab-1-công-cụ-kiểm-thử-bảo-mật-tĩnh-sast-tool)
   - [3.1. Mục tiêu & Nguyên lý hoạt động](#31-mục-tiêu--nguyên-lý-hoạt-động)
   - [3.2. Chi tiết các module trong SAST](#32-chi-tiết-các-module-trong-sast)
   - [3.3. Cài đặt môi trường & Thư viện](#33-cài-đặt-môi-trường--thư-viện)
   - [3.4. Hướng dẫn chạy và kết quả phân tích](#34-hướng-dẫn-chạy-và-kết-quả-phân-tích)
   - [3.5. Kiểm thử tự động (Unit Tests)](#35-kiểm-thử-tự-động-unit-tests)
4. [Lab 2: Công cụ kiểm thử bảo mật động (DAST Tool)](#4-lab-2-công-cụ-kiểm-thử-bảo-mật-động-dast-tool)
   - [4.1. Mục tiêu & Nguyên lý hoạt động](#41-mục-tiêu--nguyên-lý-hoạt-động)
   - [4.2. Chi tiết các module trong DAST](#42-chi-tiết-các-module-trong-dast)
   - [4.3. Cài đặt môi trường & Thư viện](#43-cài-đặt-môi-trường--thư-viện)
   - [4.4. Hướng dẫn chạy CLI và Flask Web API](#44-hướng-dẫn-chạy-cli-và-flask-web-api)
   - [4.5. Kiểm thử tự động (Unit Tests)](#45-kiểm-thử-tự-động-unit-tests)
5. [So sánh SAST và DAST](#5-so-sánh-sast-và-dast)
6. [Kết luận](#6-kết-luận)

---

## 1. TỔNG QUAN

Trong quy trình phát triển phần mềm an toàn (DevSecOps), kiểm thử bảo mật đóng vai trò then chốt nhằm phát hiện sớm các lỗ hổng mã nguồn và hành vi bất thường. Buổi thực hành này tập trung xây dựng hoàn chỉnh hai công cụ cốt lõi:

- **Lab 1 - SAST Tool (Static Application Security Testing):** Phân tích mã nguồn tĩnh (white-box) không cần thực thi chương trình. Kết hợp phân tích cây cú pháp trừu tượng (AST), so khớp mẫu Regex, kiểm tra chuẩn mã nguồn Flake8 và xuất báo cáo chuẩn quốc tế SARIF (v2.1.0).
- **Lab 2 - DAST Tool (Dynamic Application Security Testing):** Phân tích ứng dụng động (black-box/grey-box) khi chương trình đang chạy thực tế. Giám sát tài nguyên hệ thống (CPU, RAM, Open Files), lưu lượng mạng, phát hiện rò rỉ bộ nhớ/tràn số, giám sát các syscall nguy hiểm, thực thi lệnh trong môi trường cô lập (Sandbox) và cung cấp REST API qua Flask.

---

## 2. CẤU TRÚC THƯ MỤC DỰ ÁN

```text
Buoi5/
│
├── README.md                           # Báo cáo tổng hợp chi tiết 2 Lab
├── report.sarif                        # Báo cáo kết quả quét tĩnh chuẩn SARIF v2.1.0
│
├── examples/                           # Mã nguồn mẫu dùng để kiểm thử quét tĩnh
│   ├── vulnerable_01.py                # Chứa lỗi eval, hardcoded password, pickle
│   └── vulnerable_02.py                # Chứa lỗi exec, dangerous eval
│
├── rules/
│   └── default_rules.json              # Cấu hình quy tắc an toàn & mức độ nghiêm trọng
│
├── sast_tool/                          # Source code công cụ SAST (Lab 1)
│   ├── __init__.py
│   ├── ast_analyzer.py                 # Phân tích AST phát hiện hàm nguy hiểm (eval)
│   ├── vuln_pattern_matcher.py         # Khớp mẫu Regex (Hardcoded Secret, Deserialization)
│   ├── code_quality_checker.py         # Linter kiểm tra chất lượng mã (Flake8)
│   ├── security_rule_engine.py         # Động cơ đánh giá quy tắc & gán severity
│   ├── sarif_reporter.py               # Xuất báo cáo chuẩn SARIF v2.1.0
│   └── main.py                         # Điểm vào thực thi quy trình SAST
│
├── tests/                              # Unit Tests cho công cụ SAST (Lab 1)
│   ├── __init__.py
│   ├── test_ast_analyzer.py
│   ├── test_vuln_pattern_matcher.py
│   ├── test_code_quality_checker.py
│   ├── test_security_rule_engine.py
│   └── test_sarif_reporter.py
│
└── dast-tool/                          # Source code công cụ DAST (Lab 2)
    ├── __init__.py
    ├── requirements.txt                # Thư viện phụ thuộc (psutil, Flask)
    ├── runtime_monitor.py              # Giám sát tiến trình CPU, RAM, Open Files (psutil)
    ├── memory_analyzer.py              # Phân tích rò rỉ bộ nhớ (gc) và tràn số nguyên
    ├── network_traffic_analyzer.py     # Giám sát lưu lượng mạng per-interface
    ├── security_behavior_checker.py    # Phát hiện các lệnh gọi hệ thống nguy hiểm
    ├── virtual_sandbox.py              # Thực thi câu lệnh cô lập trong thư mục tạm
    ├── main.py                         # CLI chạy kiểm thử động toàn diện
    ├── app.py                          # Flask Web API cung cấp REST endpoints
    └── tests/                          # Unit Tests cho công cụ DAST (Lab 2)
        ├── __init__.py
        ├── test_runtime_monitor.py
        ├── test_memory_analyzer.py
        ├── test_network_traffic_analyzer.py
        ├── test_security_behavior_checker.py
        └── test_virtual_sandbox.py
```

---

## 3. LAB 1: CÔNG CỤ KIỂM THỬ BẢO MẬT TĨNH (SAST TOOL)

### 3.1. Mục tiêu & Nguyên lý hoạt động
Mục tiêu là xây dựng công cụ quét mã nguồn tĩnh Python, tự động phát hiện các vi phạm an toàn và chuẩn mã nguồn theo pipeline:
1. **Source Code**: Đọc nội dung file mã nguồn Python cần phân tích.
2. **Analysis Pipeline**:
   - `AST Analyzer`: Sử dụng module `ast` của Python duyệt cây cú pháp để tìm các nút `Call` có tên hàm là `eval`.
   - `Pattern Matcher`: Dùng Regular Expression tìm mật khẩu cố định (`password\s*=\s*['"].+['"]`), deserialization không an toàn (`pickle\.loads`), và hàm `eval`.
   - `Code Quality Checker`: Gọi subprocess chạy công cụ `flake8` để bắt các lỗi style, cú pháp, biến chưa dùng (PEP 8).
3. **Rule Engine**: Đối chiếu kết quả với file cấu hình `rules/default_rules.json` để gán mức độ cảnh báo (`high`, `medium`, `low`).
4. **SARIF Reporter**: Định dạng toàn bộ kết quả thành tệp `report.sarif` tương thích chuẩn quốc tế OASIS SARIF v2.1.0, cho phép mở trực tiếp trên VS Code bằng tiện ích SARIF Viewer hoặc GitHub Security Code Scanning.

### 3.2. Chi tiết các module trong SAST
- **`ast_analyzer.py`**:
  - Lớp `ASTAnalyzer` kế thừa `ast.NodeVisitor`.
  - Phương thức `visit_Call(node)`: Phát hiện mọi lời gọi hàm `eval()` cùng số dòng chính xác.
- **`vuln_pattern_matcher.py`**:
  - Lớp `VulnPatternMatcher`.
  - Định nghĩa tập regex:
    - Hardcoded Password: `password\s*=\s*['"].+['"]`
    - Insecure Deserialization: `pickle\.loads`
    - Dangerous Eval: `eval\(`
- **`code_quality_checker.py`**:
  - Lớp `CodeQualityChecker`.
  - Sử dụng `flake8` qua `subprocess.run()`, phân tích stdout để trích xuất mã lỗi, số dòng, cột và mô tả lỗi.
- **`security_rule_engine.py`**:
  - Lớp `SecurityRuleEngine`.
  - Đọc file `rules/default_rules.json`, duyệt qua danh sách phát hiện và gán nhãn `severity` tương ứng (`high`, `medium`, `low`).
- **`sarif_reporter.py`**:
  - Lớp `SarifReporter`.
  - Sử dụng thư viện `sarif_om` và `jsonpickle` để tuần tự hóa kết quả thành đối tượng SARIF Log hoàn chỉnh.

### 3.3. Cài đặt môi trường & Thư viện
Các thư viện cần thiết cho SAST Tool:
```powershell
pip install flake8 sarif-om jsonpickle
```

### 3.4. Hướng dẫn chạy và kết quả phân tích
Thực thi công cụ phân tích tệp mã nguồn mẫu:
```powershell
python -m sast_tool.main .\examples\vulnerable_01.py
```

**Kết quả màn hình Terminal:**
```text
Analysis complete.
        Report saved to report.sarif with 8 issues.
```

**Bảng chi tiết 8 lỗ hổng và vi phạm được phát hiện:**
| STT | Loại vi phạm | Mức độ | Số dòng | Mô tả |
|-----|-------------|--------|---------|-------|
| 1 | Use of eval | High | 10 | Phát hiện hàm `eval()` qua phân tích AST |
| 2 | Pattern Match | Medium | 4 | Phát hiện Hardcoded Password (`password = "secret123"`) |
| 3 | Pattern Match | Medium | 7 | Phát hiện Insecure Deserialization (`pickle.loads(...)`) |
| 4 | Pattern Match | Medium | 10 | Phát hiện gọi hàm `eval()` qua khớp mẫu Regex |
| 5 | Lint Issue | Low | 1 | F401 `'os' imported but unused` |
| 6 | Lint Issue | Low | 4 | E225 `missing whitespace around operator` |
| 7 | Lint Issue | Low | 7 | E225 `missing whitespace around operator` |
| 8 | Lint Issue | Low | 10 | E225 `missing whitespace around operator` |

Toàn bộ thông tin trên được ghi tự động vào tệp [report.sarif](file:///m:/TH%20LTANTT/Buoi5/report.sarif).

### 3.5. Kiểm thử tự động (Unit Tests)
Chạy bộ kiểm thử tự động cho SAST:
```powershell
python -m unittest discover tests
```
**Kết quả:**
```text
......
----------------------------------------------------------------------
Ran 6 tests in 0.125s

OK
```
Tất cả 6 Unit Tests đều pass 100%, bao gồm:
- `test_ast_analyzer.py`: Kiểm tra tính năng bắt hàm `eval()` qua AST.
- `test_vuln_pattern_matcher.py`: Kiểm tra độ chính xác của các mẫu Regex.
- `test_code_quality_checker.py`: Kiểm tra tích hợp linter `flake8`.
- `test_security_rule_engine.py`: Kiểm tra việc mapping quy tắc và mức độ nghiêm trọng.
- `test_sarif_reporter.py`: Kiểm tra tính hợp lệ của tệp đầu ra SARIF.

---

## 4. LAB 2: CÔNG CỤ KIỂM THỬ BẢO MẬT ĐỘNG (DAST TOOL)

### 4.1. Mục tiêu & Nguyên lý hoạt động
Mục tiêu là xây dựng bộ công cụ giám sát và kiểm thử động (DAST) theo thời gian thực:
- Theo dõi mức độ chiếm dụng tài nguyên của tiến trình (CPU %, Memory RSS, File Descriptors).
- Phát hiện rò rỉ vùng nhớ và rủi ro tràn số nguyên (Integer Overflow).
- Thu thập số liệu thống kê lưu lượng gói tin mạng (Network I/O).
- Phân tích mã nguồn đang chạy để phát hiện các cuộc gọi hàm nguy hiểm (`os.system`, `eval`, `exec`).
- Cung cấp môi trường hộp cát ảo (Virtual Sandbox) cho phép thực thi an toàn các lệnh lạ mà không ảnh hưởng hệ thống thật.
- Cung cấp giao diện dịch vụ REST API qua nền tảng Flask.

### 4.2. Chi tiết các module trong DAST
- **`runtime_monitor.py`**:
  - Lớp `RuntimeMonitor(pid)`.
  - `get_cpu_usage()`: Đo tỷ lệ CPU sử dụng trong khoảng thời gian `interval=1.0` giây.
  - `get_memory_usage()`: Trả về lượng RAM vật lý đang chiếm dụng (RSS tính theo bytes).
  - `get_open_files()`: Liệt kê danh sách các tệp tin mà tiến trình đang mở.
- **`memory_analyzer.py`**:
  - Lớp `MemoryAnalyzer`.
  - `check_memory_leaks()`: Kích hoạt `gc.collect()` và rà soát danh sách đối tượng không thể thu hồi trong `gc.garbage` có phương thức hủy `__del__`.
  - `check_overflow(value)`: Kiểm tra nếu giá trị vượt quá giới hạn số nguyên có dấu 64-bit ($2^{63}$).
- **`network_traffic_analyzer.py`**:
  - Lớp `NetworkTrafficAnalyzer`.
  - `get_network_stats()`: Thu thập thống kê lưu lượng truyền/nhận theo từng card mạng vật lý và ảo (`pernic=True`).
- **`security_behavior_checker.py`**:
  - Lớp `SecurityBehaviorChecker`.
  - `suspicious_calls()`: Quét tìm các lời gọi hàm nguy hiểm (`os.system`, `eval`, `exec`) bên trong mã nguồn thực thi.
- **`virtual_sandbox.py`**:
  - Lớp `VirtualSandbox`.
  - `__init__()`: Tạo một thư mục tạm thời độc lập bằng `tempfile.mkdtemp()`.
  - `run_isolated(command)`: Thực thi lệnh con với thư mục làm việc đặt tại thư mục tạm (`cwd=self.temp_dir`), bắt giữ `stdout` và `stderr`.
- **`main.py`**: Chương trình CLI tổng hợp kiểm tra đồng thời tất cả các module trên tiến trình hiện hành.
- **`app.py`**: Ứng dụng Flask REST API phục vụ việc tích hợp vào hệ thống giám sát tập trung.

### 4.3. Cài đặt môi trường & Thư viện
Cài đặt các gói phụ thuộc từ [dast-tool/requirements.txt](file:///m:/TH%20LTANTT/Buoi5/dast-tool/requirements.txt):
```powershell
cd dast-tool
pip install -r .\requirements.txt
```
*(Bao gồm: `psutil`, `Flask`)*

### 4.4. Hướng dẫn chạy CLI và Flask Web API

#### a) Chạy công cụ dòng lệnh (CLI):
```powershell
cd dast-tool
python main.py
```
*Hoặc đứng từ thư mục gốc:*
```powershell
python .\dast-tool\main.py
```

**Kết quả thực thi mẫu:**
```text
[+] Monitoring current process: 12428
CPU Usage: 0.0
Memory Usage: 20140032
Open Files: [popenfile(path='C:\Windows\System32\en-US\KernelBase.dll.mui', fd=-1)]
Memory Leaks: []
Overflow Test: True
Network Stats: {'Wi-Fi': snetio(bytes_sent=615703097, bytes_recv=357211822, ...), ...}
Suspicious Calls: ['os.system', 'eval', 'exec']
Sandbox stdout: Hello Sandbox
Sandbox stderr: 
```

#### b) Khởi chạy Flask Web API Server:
```powershell
cd dast-tool
python app.py
```
Server sẽ lắng nghe tại `http://0.0.0.0:5000`.

**Danh sách các API Endpoints:**
| Method | Endpoint | Mô tả | Dữ liệu trả về (JSON) |
|--------|----------|-------|-----------------------|
| `GET` | `/api/monitor` | Giám sát CPU, RAM, Open Files | `{"cpu_usage": 0.0, "memory_usage": 20480000, "open_files": [...]}` |
| `GET` | `/api/memory` | Kiểm tra rò rỉ RAM & tràn số | `{"memory_leaks": "[]", "overflow_test": true}` |
| `GET` | `/api/network` | Thống kê I/O card mạng | `{"network_stats": {"Wi-Fi": {...}, "Ethernet": {...}}}` |
| `GET` | `/api/security` | Danh sách syscall nguy hiểm | `{"suspicious_calls": ["os.system", "eval", "exec"]}` |
| `POST` | `/api/sandbox` | Chạy lệnh trong sandbox | Request: `{"command": "echo Hello"}`<br>Response: `{"stdout": "Hello\n", "stderr": ""}` |

### 4.5. Kiểm thử tự động (Unit Tests)
Chạy bộ kiểm thử tự động cho DAST:
```powershell
cd dast-tool
python -m unittest discover tests
```
**Kết quả:**
```text
.....
----------------------------------------------------------------------
Ran 5 tests in 1.033s

OK
```
Tất cả 5 Unit Tests đều pass 100%, bao gồm:
- `test_runtime_monitor.py`: Kiểm tra đo đạc CPU (%) và RAM (bytes >= 0).
- `test_memory_analyzer.py`: Kiểm tra nhận diện tràn số nguyên `2**64` (> $2^{63}$) và số thông thường.
- `test_network_traffic_analyzer.py`: Kiểm tra cấu trúc dữ liệu trả về của network stats dạng `dict`.
- `test_security_behavior_checker.py`: Kiểm tra kết quả trả về của danh sách syscall nguy hiểm dạng `list`.
- `test_virtual_sandbox.py`: Kiểm tra khả năng thực thi lệnh cô lập và bắt đúng kết quả `stdout`, `stderr`.

---

## 5. SO SÁNH SAST VÀ DAST

| Tiêu chí | SAST (Static Application Security Testing) | DAST (Dynamic Application Security Testing) |
|---|---|---|
| **Phương pháp tiếp cận** | Kiểm thử hộp trắng (White-box testing) | Kiểm thử hộp đen / xám (Black-box / Grey-box testing) |
| **Yêu cầu thực thi** | Không cần chạy chương trình (phân tích mã nguồn) | Bắt buộc chương trình phải đang hoạt động |
| **Thời điểm áp dụng** | Giai đoạn Code / Commit (Shift-Left Security) | Giai đoạn Test / Staging / Production |
| **Đối tượng kiểm tra** | Cú pháp, AST, Regex mẫu, Coding style (PEP 8) | Tiến trình (PID), CPU/RAM, Network I/O, Hành vi runtime |
| **Khả năng phát hiện** | Lỗi logic cú pháp, hardcoded credentials, API nguy hiểm | Lỗi tràn bộ nhớ, rò rỉ RAM, bất thường mạng, lỗi cấu hình runtime |
| **Ưu điểm** | Tìm chính xác số dòng lỗi; chi phí sửa chữa rẻ; phát hiện sớm | Phát hiện lỗi thực tế của hệ thống; tỷ lệ False Positive thấp hơn |
| **Nhược điểm** | Dễ báo lỗi giả (False Positives); không thấy được ngữ cảnh chạy | Khó chỉ ra chính xác dòng code gây lỗi; cần môi trường thực thi hoàn chỉnh |
| **Định dạng báo cáo tiêu biểu** | SARIF (Static Analysis Results Interchange Format) | JSON REST API, Log alerts, Dashboard metrics |

> **Nhận xét kết hợp:** Trong thực tế, SAST và DAST bổ trợ lẫn nhau để xây dựng mô hình bảo mật nhiều lớp (Defense-in-Depth). SAST giúp lập trình viên viết code sạch ngay từ đầu, trong khi DAST đảm bảo ứng dụng chạy an toàn trong môi trường vận hành thực tế.

---

## 6. KẾT LUẬN

1. **Về mặt kỹ thuật:**
   - Đã xây dựng hoàn chỉnh và chạy thực nghiệm thành công cả 2 công cụ **SAST Tool** và **DAST Tool**.
   - Cả hai dự án đều được module hóa rõ ràng, dễ bảo trì, mở rộng và tích hợp vào quy trình CI/CD.
   - Toàn bộ các bộ kiểm thử tự động (Unit Tests) trên cả 2 lab (6 tests cho SAST và 5 tests cho DAST) đều đạt tỷ lệ pass **100%**.
2. **Về mặt ứng dụng:**
   - Báo cáo SARIF tạo ra tương thích chuẩn OASIS, có thể tích hợp với các công cụ DevSecOps hiện đại như GitHub Advanced Security, SonarQube, VS Code SARIF Viewer.
   - Bộ API của DAST Tool cho phép xây dựng các Dashboard giám sát tài nguyên và sandbox phân tích phần mềm độc hại tự động.
