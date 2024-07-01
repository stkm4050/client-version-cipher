import pandas as pd
import glob
import os
import argparse

def calculate_ssh_and_cipher_percentages(directory_path):
    # 指定されたディレクトリ内のすべてのCSVファイルを取得
    csv_files = glob.glob(os.path.join(directory_path, "*.csv"))
    
    # データを格納する辞書を初期化
    ssh_versions = {}
    ciphers = {}

    # 各CSVファイルを読み込んでデータを集計
    for file in csv_files:
        try:
            # CSVファイルを読み込む
            df = pd.read_csv(file)
        except pd.errors.ParserError as e:
            print(f"エラーが発生しました: {file}")
            print(e)
            continue  # エラーが発生したファイルをスキップ

        # SSH Versionの割合を集計
        for index, row in df.iterrows():
            ssh_version = row['SSHversion']
            ssh_percentage = row['Percentage']
            if ssh_version not in ssh_versions:
                ssh_versions[ssh_version] = 0
            ssh_versions[ssh_version] += ssh_percentage
        
        # Cipherの割合を集計（空白でない場合）
        for index, row in df.iterrows():
            cipher = row['Cipher']
            if pd.notna(cipher) and cipher and 'Percentage.1' in row:
                cipher_percentage = row['Percentage.1']  # 2つ目のPercentage列を使用
                if cipher not in ciphers:
                    ciphers[cipher] = 0
                ciphers[cipher] += cipher_percentage

    # 全体の割合を計算
    total_ssh_percentage = sum(ssh_versions.values())
    total_cipher_percentage = sum(ciphers.values())

    # 全体の割合に対する個別割合を計算し、ソート
    ssh_versions_percentage = {k: v / total_ssh_percentage * 100 for k, v in ssh_versions.items()}
    sorted_ssh_versions = sorted(ssh_versions_percentage.items(), key=lambda item: item[1], reverse=True)

    ciphers_percentage = {k: v / total_cipher_percentage * 100 for k, v in ciphers.items()}
    sorted_ciphers = sorted(ciphers_percentage.items(), key=lambda item: item[1], reverse=True)

    # 結果を表示
    print("SSH Version,percentage")
    for version, percentage in sorted_ssh_versions:
        print(f"{version},{percentage:.2f}")

    print("\nCipher,percentage")
    for cipher, percentage in sorted_ciphers:
        print(f"{cipher},{percentage:.2f}")

if __name__ == "__main__":
    # コマンドライン引数を処理するためのargparseを設定
    parser = argparse.ArgumentParser(description="SSHバージョンと暗号方式の割合を計算するスクリプト")
    parser.add_argument("directory", help="CSVファイルが含まれるディレクトリのパス")

    # 引数を解析
    args = parser.parse_args()

    # 指定されたディレクトリパスを使用して関数を呼び出し
    calculate_ssh_and_cipher_percentages(args.directory)
