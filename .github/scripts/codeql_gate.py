#!/usr/bin/env python3
"""Gate do CodeQL: falha o job se o SARIF tiver achados com security-severity >= limite.

Escala do GitHub: critical >= 9.0 | high 7.0-8.9 | medium 4.0-6.9 | low 0.1-3.9
Uso: python3 codeql_gate.py <pasta-ou-arquivo-sarif> [--threshold 7.0]
"""
import argparse
import json
import os
import pathlib
import sys


def nivel(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "none"


def indice_de_regras(run: dict) -> dict:
    # No CodeQL as regras ficam no driver e, principalmente, nas extensions (query packs)
    tool = run.get("tool", {})
    componentes = [tool.get("driver", {})] + tool.get("extensions", [])
    return {r.get("id"): r for c in componentes for r in (c.get("rules") or [])}


def arquivos_sarif(caminho: str):
    p = pathlib.Path(caminho)
    return [p] if p.is_file() else sorted(p.glob("*.sarif"))


def anotacao(texto: str) -> str:
    # GitHub interpreta %, : e , em comandos de workflow
    return texto.replace("%", "%25").replace(":", "%3A").replace(",", "%2C")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sarif")
    ap.add_argument("--threshold", type=float, default=7.0)
    args = ap.parse_args()

    arquivos = arquivos_sarif(args.sarif)
    if not arquivos:
        print(f"::error::Nenhum .sarif encontrado em {args.sarif}")
        return 2

    bloqueantes = []
    for arq in arquivos:
        dados = json.loads(arq.read_text(encoding="utf-8"))
        for run in dados.get("runs", []):
            regras = indice_de_regras(run)
            for res in run.get("results", []):
                if res.get("suppressions"):
                    continue
                rid = res.get("ruleId") or res.get("rule", {}).get("id")
                props = regras.get(rid, {}).get("properties", {})
                try:
                    score = float(props.get("security-severity", 0))
                except (TypeError, ValueError):
                    score = 0.0
                if score < args.threshold:
                    continue
                loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
                arquivo = loc.get("artifactLocation", {}).get("uri", "?")
                linha = loc.get("region", {}).get("startLine", 1)
                msg = (res.get("message", {}).get("text") or "").splitlines()
                bloqueantes.append((score, nivel(score), rid, arquivo, linha, (msg[0] if msg else "")[:200]))

    bloqueantes.sort(reverse=True)
    resumo = os.environ.get("GITHUB_STEP_SUMMARY")

    if not bloqueantes:
        print(f"OK: nenhum achado com security-severity >= {args.threshold}")
        if resumo:
            with open(resumo, "a", encoding="utf-8") as f:
                f.write(f"### CodeQL gate: aprovado (limite {args.threshold})\n")
        return 0

    for score, lvl, rid, arquivo, linha, msg in bloqueantes:
        titulo = anotacao(f"{rid} ({lvl} {score})")
        print(f"::error file={arquivo},line={linha},title={titulo}::{msg}")

    if resumo:
        with open(resumo, "a", encoding="utf-8") as f:
            f.write(f"### CodeQL gate: reprovado — {len(bloqueantes)} achado(s) >= {args.threshold}\n\n")
            f.write("| Severidade | Score | Regra | Local |\n|---|---|---|---|\n")
            for score, lvl, rid, arquivo, linha, _ in bloqueantes:
                f.write(f"| {lvl} | {score} | `{rid}` | `{arquivo}:{linha}` |\n")

    print(f"FALHA: {len(bloqueantes)} achado(s) high/critical")
    return 1


if __name__ == "__main__":
    sys.exit(main())
