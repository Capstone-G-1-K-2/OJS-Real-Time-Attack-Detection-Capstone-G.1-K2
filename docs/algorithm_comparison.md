# Komparasi Algoritma Klasifikasi Log HTTP

Dokumen ini merangkum kelebihan dan kekurangan tiga algoritma baseline untuk klasifikasi log HTTP: Random Forest, SVM, dan XGBoost.

## 1. Random Forest

Kelebihan:
- Baseline kuat untuk data tabular hasil feature engineering.
- Tahan terhadap overfitting dibanding satu decision tree.
- Tidak terlalu sensitif terhadap scaling fitur.
- Memiliki feature importance bawaan untuk interpretasi awal.

Kekurangan:
- Ukuran model bisa besar saat jumlah tree tinggi.
- Inferensi bisa lebih lambat dari model linear jika tree sangat banyak.
- Kurang kuat dibanding boosting pada pola interaksi kompleks.

Kapan dipakai:
- Baseline awal yang cepat dan stabil saat struktur fitur sudah jelas.

## 2. SVM (Linear/RBF)

Kelebihan:
- Cocok untuk data teks sparse setelah TF-IDF.
- Sering memberi performa baik pada dimensi tinggi.
- Decision boundary tegas untuk pemisahan kelas.

Kekurangan:
- Training mahal pada data besar (terutama kernel non-linear).
- Membutuhkan tuning C/kernel yang lebih sensitif.
- Probabilitas prediksi sering perlu kalibrasi tambahan.

Kapan dipakai:
- Eksperimen teks dengan ukuran data menengah sebagai pembanding model tree-based.

## 3. XGBoost

Kelebihan:
- Sangat kuat untuk data tabular dan interaksi non-linear.
- Umumnya memberi akurasi tinggi di banyak kompetisi/benchmark.
- Mendukung regularization dan kontrol kompleksitas model yang baik.

Kekurangan:
- Hyperparameter lebih banyak sehingga tuning lebih kompleks.
- Training lebih berat dibanding model linear sederhana.
- Interpretasi model perlu alat tambahan (misalnya SHAP) agar lebih jelas.

Kapan dipakai:
- Kandidat utama saat mengejar performa terbaik pada baseline tabular.

## Ringkasan Praktis untuk Tugas

- Random Forest: baseline stabil dan cepat.
- SVM: baseline teks yang kuat, tetapi sensitif skala dan ukuran data.
- XGBoost: kandidat performa tertinggi, dengan biaya tuning lebih besar.

Rekomendasi urutan eksperimen awal:
1. Random Forest
2. SVM (Linear)
3. XGBoost
4. Bandingkan metrik: F1, precision, recall, ROC-AUC, accuracy
