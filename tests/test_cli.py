from cvescout import __main__ as cli
from cvescout import sources


def _products(*items):
    return {"products": [
        {"cpe": cpe, "title": title, "deprecated": bool(repl), "replaced_by": repl} for cpe, title, repl in items
    ]}


def test_cpe_names_pass_through_without_lookup(monkeypatch):
    monkeypatch.setattr(sources, "find_cpe", lambda *a, **k: (_ for _ in ()).throw(AssertionError("lookup")))
    for value in ("haxx:curl", "o:linux:linux_kernel", "cpe:2.3:a:haxx:curl"):
        assert cli._resolve_cpe(value) == value


def test_bare_name_takes_best_match_and_says_so(monkeypatch, capsys):
    monkeypatch.setattr(sources, "find_cpe", lambda q, limit: _products(
        ("haxx:curl", "Haxx Curl", None), ("curl_project:curl", "curl Project curl", None),
    ))
    assert cli._resolve_cpe("curl") == "haxx:curl"
    err = capsys.readouterr().err
    assert "--cpe curl -> haxx:curl" in err and "curl_project:curl" in err


def test_deprecated_best_match_follows_replacement(monkeypatch, capsys):
    monkeypatch.setattr(sources, "find_cpe", lambda q, limit: _products(("curl:curl", "Curl", "haxx:curl")))
    assert cli._resolve_cpe("curl") == "haxx:curl"


def test_unknown_name_is_an_error(monkeypatch, capsys):
    monkeypatch.setattr(sources, "find_cpe", lambda q, limit: {"products": []})
    assert cli.main(["feed", "--cpe", "nosuchproduct"]) == 1
    assert "--keyword nosuchproduct" in capsys.readouterr().err


def test_no_arguments_prints_help(capsys):
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "feed options" in out and "--poc" in out


def test_unknown_option_points_to_command_help(capsys):
    import pytest

    with pytest.raises(SystemExit) as e:
        cli.main(["feed", "-poc"])
    assert e.value.code == 2
    err = capsys.readouterr().err
    assert "cvescout feed: error: unrecognized arguments: -poc" in err
    assert "see: cvescout feed --help" in err


def test_row_text_is_cut_on_a_terminal_and_wrapped_with_full(monkeypatch, capsys):
    import os

    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli.shutil, "get_terminal_size", lambda *a: os.terminal_size((60, 24)))
    text = "word " * 30
    cli._print_row("ROW ", text, full=False)
    line = capsys.readouterr().out.rstrip("\n")
    assert len(line) <= 60 and line.endswith("…")

    cli._print_row("ROW ", text, full=True)
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "ROW" and all(l.startswith(cli.INDENT) for l in out[1:])
    assert " ".join(" ".join(out[1:]).split()) == text.strip()


def test_piped_output_is_not_cut(monkeypatch, capsys):
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: False, raising=False)
    cli._print_row("ROW ", "word " * 100, full=False)
    assert "…" not in capsys.readouterr().out
