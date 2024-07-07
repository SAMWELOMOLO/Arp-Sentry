# Configuration file for the Sphinx documentation builder.

# -- Project information

from datetime import date

import os
import sys
sys.path.insert(0, os.path.abspath('../../arpsentry'))


project = 'ARP Spoofing Detection Tool'
author = 'Samwel Omolo'
release = '0.1'
version = '0.1.0'
copyright=f"{date.today().year}, Samwel Omolo"

# -- General configuration

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx_autodoc_typehints',
]

templates_path = ['_templates']
exclude_patterns = []

# -- Options for HTML output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Other configurations...
autodoc_member_order = 'bysource'
napoleon_google_docstring = True
napoleon_numpy_docstring = True
