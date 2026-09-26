"""Montagem exclusiva do portátil pelo BAT. Não é importado pelo runtime."""
from pathlib import Path
import argparse
import hashlib
import shutil
import struct
import zipfile
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from desenvolvimento.scan_branding import require_clean


def file_digest(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
    return digest


def validate_executable(path):
    """Rejeita ausência/arquivo inválido; não substitui teste nativo do EXE."""
    with Path(path).open('rb') as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b'MZ':
            raise ValueError('ConfiguradorTI.exe ausente ou sem cabeçalho Windows PE válido.')
        offset = struct.unpack_from('<I', header, 60)[0]
        if offset < 64 or offset > Path(path).stat().st_size - 4:
            raise ValueError('Cabeçalho PE inválido.')
        stream.seek(offset)
        if stream.read(4) != b'PE\0\0': raise ValueError('Assinatura PE inválida.')


def build_portable(executable, readme, output):
    executable, readme, output = Path(executable), Path(readme), Path(output)
    validate_executable(executable)
    if not readme.is_file(): raise FileNotFoundError('LEIA-ME final não encontrado.')
    require_clean(executable);require_clean(readme)
    output.mkdir(parents=True, exist_ok=True)
    index = 0
    while True:
        name = 'Configurador_TI_PORTATIL' + (f'_{index}' if index else '')
        folder, archive = output/name, output/(name+'.zip')
        if folder.exists() or folder.is_symlink() or archive.exists() or archive.is_symlink():
            index += 1; continue
        try:
            zip_stream = archive.open('xb')
        except FileExistsError:
            index += 1; continue
        try:
            folder.mkdir()
        except FileExistsError:
            zip_stream.close(); archive.unlink()  # Somente reserva própria vazia.
            index += 1; continue
        except BaseException:
            zip_stream.close(); archive.unlink(); raise
        break
    try:
        shutil.copy2(executable, folder/'ConfiguradorTI.exe')
        shutil.copy2(readme, folder/'LEIA-ME.txt')
        # Lista permitida explícita: nunca varrer fontes/dados para compor o ZIP.
        with zip_stream, zipfile.ZipFile(zip_stream, 'w', zipfile.ZIP_DEFLATED) as z:
            for filename in ('ConfiguradorTI.exe', 'LEIA-ME.txt'):
                z.write(folder/filename, 'Configurador_TI/'+filename)
        with zipfile.ZipFile(archive) as z:
            if z.testzip() is not None: raise ValueError('Falha de integridade no ZIP portátil.')
            for filename in ('ConfiguradorTI.exe', 'LEIA-ME.txt'):
                with z.open('Configurador_TI/'+filename) as stream, (folder/filename).open('rb') as source:
                    if file_digest(stream).digest() != file_digest(source).digest():
                        raise ValueError('Conteúdo do ZIP diverge da pasta portátil.')
    except BaseException:
        zip_stream.close()
        archive.unlink(missing_ok=True)  # Nunca remove um ZIP anterior.
        raise  # Pasta parcial preservada; próxima tentativa recebe outro número.
    require_clean(archive)
    return folder, archive


def main():
    parser = argparse.ArgumentParser(description='Monta Configurador_TI_PORTATIL e ZIP sem fontes.')
    parser.add_argument('--exe', required=True)
    parser.add_argument('--readme', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    folder, archive = build_portable(args.exe, args.readme, args.output)
    print(f'Pasta final: {folder}\nZIP para distribuir: {archive}')
    with archive.open('rb') as stream:
        print('SHA-256 do ZIP: '+file_digest(stream).hexdigest())
    print('Usuário final: extraia o ZIP e abra ConfiguradorTI.exe.')


if __name__ == '__main__':
    main()
