from bs4 import BeautifulSoup as bs
import esprima
import glob
import shutil
from pathlib import Path
import os
import argparse

def extract_script_from_html(html: str):
    soup = bs(html, "html.parser")
    for script in soup.find_all("script"):
        yield script

def tokenize_html(html: str):
    for script in extract_script_from_html(html):
        for program in script:
            yield esprima.tokenize(program)

def tokenize(file_path: str, js_file=True):
    try:
        with open(file_path, "r", errors='surrogateescape') as f:
            if js_file:
                yield esprima.tokenize(f.read())
            else:
                yield from tokenize_html(f.read())
    except:
        yield []

def is_valid_path(path: str):
    ignore_files_pattern = ['misc', 'ignore']
    return all(ignore_pattern not in path for ignore_pattern in ignore_files_pattern)

def get_token_from_file(malicious: bool, js_file=True):
    path_pattern = "MALICIOUS/**/*" if malicious else "BENIGN/**/*" 
    path_pattern = f"{path_pattern}.js" if js_file else f"{path_pattern}.html"

    for file_path in glob.iglob(path_pattern, recursive=True):
        if is_valid_path(file_path):
            yield from tokenize(file_path, js_file)
    
def get_all_js_token(malicious: bool):
    yield from get_token_from_file(malicious, js_file=True)
    yield from get_token_from_file(malicious, js_file=False)

def export_file(from_dir: str, malicious: str, js_file=True):
    path_pattern = f"{from_dir}/**/*.js" if js_file else f"{from_dir}/**/*.html"
    to_dir = "MALICIOUS" if malicious else "BENIGN"
    for file_path in glob.iglob(path_pattern, recursive=True):
        if os.path.isdir(file_path):
            continue
        to_dir_path = os.path.join(to_dir, os.path.dirname(file_path))
        Path(to_dir_path).mkdir(parents=True, exist_ok=True)
        shutil.copy(file_path, to_dir_path)

def export_html_and_js(from_dir: str, malicious=True):
    export_file(from_dir, malicious, js_file=True)
    export_file(from_dir, malicious, js_file=False)

def main():
    parser = argparse.ArgumentParser(description='Export js and HTML files')
    parser.add_argument('-s', dest="from_dir", type=str, required=True, help="The source directory from which the js and html files are copied")
    parser.add_argument('-m', "--malicious", dest="malicious", action='store_true', help="Indicates if the files are malicious or benign")
    args = parser.parse_args()
    export_html_and_js(args.from_dir, args.malicious)

if __name__ == "__main__":
    main()