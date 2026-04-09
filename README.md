# Sistem Deteksi Serangan OJS Berbasis Machine Learning

## Deskripsi Proyek
Proyek ini merupakan implementasi sistem **deteksi serangan siber secara real-time** pada platform **Open Journal Systems (OJS)** menggunakan pendekatan **analisis log dan Machine Learning**.

Sistem ini menganalisis log aktivitas server dan aplikasi untuk mengidentifikasi pola aktivitas mencurigakan yang berpotensi merupakan eksploitasi kerentanan keamanan yang telah terdokumentasi (CVE).

Jika sistem mendeteksi aktivitas serangan, maka sistem akan secara otomatis mengirimkan **notifikasi peringatan melalui Telegram Bot** kepada administrator.

Proyek ini dikembangkan sebagai bagian dari **Capstone Project Fakultas Ilmu Komputer Universitas Brawijaya**.

---

# Latar Belakang
Open Journal Systems (OJS) merupakan platform manajemen penerbitan jurnal ilmiah berbasis web yang banyak digunakan oleh institusi akademik di Indonesia.

Namun, masih banyak implementasi OJS yang menggunakan **versi lama** sehingga memiliki berbagai kerentanan keamanan seperti:

- Cross Site Scripting (XSS)
- Cross Site Request Forgery (CSRF)
- Remote Code Execution (RCE)
- Brute Force Attack

Tanpa sistem monitoring yang baik, serangan biasanya baru terdeteksi setelah terjadi gangguan layanan atau kebocoran data.

Oleh karena itu, proyek ini bertujuan membangun **sistem deteksi serangan otomatis berbasis Machine Learning** yang mampu mengidentifikasi pola serangan dari data log secara cepat.

---

# Arsitektur Sistem

Sistem terdiri dari beberapa komponen utama:

1. **Pengumpulan Log**
   - Mengambil data log dari server dan aplikasi OJS.

2. **Preprocessing & Feature Engineering**
   - Mengubah log mentah menjadi data terstruktur yang dapat diproses oleh model Machine Learning.

3. **Model Machine Learning**
   - Mengklasifikasikan aktivitas log menjadi:
     - Aktivitas normal
     - Aktivitas serangan

4. **Pipeline Deteksi Real-Time**
   - Memproses log secara berkelanjutan untuk melakukan prediksi secara cepat.

5. **Sistem Notifikasi**
   - Mengirimkan peringatan otomatis melalui **Telegram Bot** ketika terdeteksi aktivitas serangan.

---

# Teknologi yang Digunakan

## Bahasa Pemrograman
- Python 3

## Machine Learning
- Scikit-Learn
- XGBoost

## Pengolahan Data
- Pandas
- NumPy

## Tools & MLOps
- MLflow
- Python pickle (built-in) for model serialization
- Docker
- Git & GitHub

## Integrasi Notifikasi
- Telegram Bot API

---

# Dataset

Dataset yang digunakan dalam penelitian ini berasal dari lingkungan uji yang terdiri dari:

### Aktivitas Normal
- Login pengguna
- Upload artikel
- Manajemen pengguna
- Aktivitas editorial

### Aktivitas Serangan
Serangan direproduksi berdasarkan kerentanan CVE yang relevan dengan OJS seperti:

- XSS
- CSRF
- RCE
- Brute Force

Target dataset:
- Minimal **2000 entri log**
- Terdiri dari **aktivitas normal dan aktivitas serangan**

---

# Tujuan Proyek

Tujuan dari proyek ini adalah:

1. Mereproduksi beberapa skenario serangan berbasis CVE pada OJS.
2. Mengumpulkan dan melabeli dataset log aktivitas sistem.
3. Mengembangkan model Machine Learning untuk klasifikasi log.
4. Mengimplementasikan sistem deteksi serangan secara **real-time atau near real-time**.
5. Mengirimkan notifikasi otomatis kepada administrator ketika serangan terdeteksi.

---

# Output Sistem

Proyek ini menghasilkan **prototype (Proof of Concept)** yang terdiri dari:

- Modul pengumpulan log
- Model Machine Learning untuk deteksi serangan
- Pipeline analisis log real-time
- Sistem notifikasi otomatis melalui Telegram

---

# Tim Pengembang

Nama Tim: **Manut Pak Eko**

| Nama | Peran |
|-----|-----|
| Pascal Brahmantyo Hadiyanto | Backend Engineer |
| Ryan Shava Afifi | Data Engineer |
| Achmad Alvian Prasetio | ML Engineer |
| Aero Nathanael Silalahi | Data Engineer |
| Sandhika Rizqi Ramadhan | Project Manager |
| Nizar Maulana Wahyudi | Data Engineer / Backend |
| Farhat Hidayat | Project Manager |

---

# Deployment

Sistem dirancang untuk dijalankan menggunakan **Docker container** sehingga mudah di-deploy pada berbagai lingkungan seperti:

- Virtual Machine
- Cloud Server
- Lingkungan uji lokal

Spesifikasi minimal:
- 1 vCPU
- 1–2 GB RAM

---

# Pengembangan Selanjutnya

Beberapa pengembangan yang dapat dilakukan ke depan:

- Integrasi dengan sistem monitoring keamanan (SIEM)
- Dashboard visualisasi monitoring serangan
- Penambahan jenis serangan yang dapat dideteksi
- Implementasi sistem pencegahan otomatis

---

# Lisensi

Proyek ini dikembangkan untuk tujuan penelitian dan pengembangan akademik.
