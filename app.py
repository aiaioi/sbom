from flask import Flask, request, render_template
from flask import send_file
import os
import shutil
import subprocess

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/add', methods=['POST', "GET"])
def add():
    #output_fileの中身を空にする
    shutil.rmtree('output_file')
    #再度フォルダ作成
    os.mkdir('output_file')

    #提出ファイル取得
    file = request.files["file"]
    #保存
    file.save(os.path.join('submit_file', file.filename))
    
    submit_path = "submit_file/" + file.filename
    output_path = "output_file/sbom.xml"

    format = request.form.get('format')
    format1 = request.form.get('format1')

    if format == "CycloneDX" and format1 == "xml":
        subprocess.run(["syft submit_file -o cyclonedx-xml | tee output_file/sbom.xml"],shell =True)
        file_name = "sbom.xml"

#   if format == "CycloneDX" and format1 == "json":
#   サブプロセスでLinuxでCycloneDXを実行
#       subprocess.run(["cyclonedx-py", "-r", "-i", submit_path, "-o", output_path])
    
    if format == "CycloneDX" and format1 == "json":
        subprocess.run(["syft submit_file -o cyclonedx-json | tee output_file/sbom.json"],shell =True)
        file_name = "sbom.json"
    
    else:
        return render_template("result.html")
#render_template('result.html', result=result)

 #データ処理後削除
    shutil.rmtree('submit_file')
    #再度フォルダ作成
    os.mkdir('submit_file')
    #解析結果をダウンロードさせる
    return send_file("./output_file/"+file_name,
    mimetype="text/plain",
    as_attachment=True,
    )

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

##http://35.79.185.141:5000/
