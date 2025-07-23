
````markdown
# VeriKNN

VeriKNN is a verifiable and privacy-preserving k-nearest neighbors (KNN) search framework. It ensures the correctness of search results while protecting user data and queries.

## 🧠 Features

- **Privacy-preserving**: Protects both user data and search queries.
- **Verifiable**: Provides verifiable results to detect server misbehavior.
- **Efficient**: Designed to minimize computation and communication overhead.

## 📦 Directory Structure

```text
VeriKNN/
├── Data/
│   ├── data.py
│   ├── data_high_diverse.py
│   ├── normalized_array.npy
│   └── setup.py
├── Server/
│   ├── server_1.py
│   ├── server_1_high_diverse.py
│   ├── server_2.py
│   └── server_2_high_diverse.py
├── main.py
├── main_high_diverse.py
├── pytroy.cpython-39-x86_64-linux-gnu.so
└── README.md
````

## 🚀 Getting Started

1. Clone this repository:

```bash
git clone https://github.com/DeCloveC/VeriKNN.git
cd VeriKNN
```


2. Run the demo:

```bash
python3 main.py
```

For high diversity dataset test:

```bash
python3 main_high_diverse.py
```

## 📁 Key Generation

Run the following scripts to prepare the key:

```bash
python3 Data/setup.py
```

## 📁 Data Generation

Run the following scripts to prepare the data:

```bash
python3 Data/data.py
python3 Data/data_high_diverse.py
```



## 📜 License

This project is licensed under the MIT License.

