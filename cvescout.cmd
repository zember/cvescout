@echo off
rem Run cvescout from this project's virtualenv without activating it.
rem Add this folder to PATH to call "cvescout" from any cmd window.
"%~dp0.venv\Scripts\cvescout.exe" %*
