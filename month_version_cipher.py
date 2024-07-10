import pandas as pd
import glob
import os
import argparse

def calculate_ssh_and_cipher_percentages(directory_path):
    # 指定されたディレクトリ内のすべてのCSVファイルを取得
    csv_files = glob.glob(os.path.join(directory_path, "*.csv"))
    
    # データを格納する辞書を初期化
    ssh_versions = {}
    version_ciphers = {}
    ssh_versions_percentage = {}

    # 各CSVファイルを読み込んでデータを集計
    for file in csv_files:
        try:
            # CSVファイルを読み込む
            df = pd.read_csv(file)
            # percentageの値をint化
            df['percentage'] = pd.to_numeric(df['percentage'], errors='coerce')
        except pd.errors.ParserError as e:
            print(f"エラーが発生しました: {file}")
            print(e)
            continue  # エラーが発生したファイルをスキップ

        # SSH Versionの割合を集計
        for index, row in df.iterrows():  #
            ssh_version = row['SSHversion']
            version_cipher = ssh_version.split('/')
            ssh_percentage = row['percentage']
            if ssh_version not in version_ciphers:
                version_ciphers[ssh_version] = 0
            version_ciphers[ssh_version] += ssh_percentage
            if version_cipher[0] not in ssh_versions:
                ssh_versions[version_cipher[0]] = 0
            ssh_versions[version_cipher[0]] += ssh_percentage
        
    # 全体の割合を計算
    for version_cipher in version_ciphers:
        version = version_cipher.split('/')
        for ssh_version in ssh_versions:
            if version[0] == ssh_version:
                ssh_versions_percentage[version_cipher] = version_ciphers[version_cipher] / ssh_versions[ssh_version] * 100

    # 全体の割合に対する個別割合を計算し、ソート
    sorted_ssh_versions = sorted(ssh_versions_percentage.items(), key=lambda item: item[1], reverse=True)

    # 結果を表示
    print("Version/Cipher,Percentage")
    for version, percentage in sorted_ssh_versions:
        print(f"{version},{percentage:.2f}")

if __name__ == "__main__":
    # コマンドライン引数を処理するためのargparseを設定
    parser = argparse.ArgumentParser(description="SSHバージョンと暗号方式の割合を計算するスクリプト")
    parser.add_argument("directory", help="CSVファイルが含まれるディレクトリのパス")

    # 引数を解析
    args = parser.parse_args()

    # 指定されたディレクトリパスを使用して関数を呼び出し
    calculate_ssh_and_cipher_percentages(args.directory)
