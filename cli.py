#!/usr/bin/env python3
import sys
import os

# Add python directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "python"))

from rockcrypter.cli import main

if __name__ == "__main__":
    main()
