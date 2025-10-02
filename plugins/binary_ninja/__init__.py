# -*- coding: utf-8 -*-
# pylint: disable=invalid-name,unused-argument
"""REcover Binary Ninja plug-in."""

__author__ = "Athanasios Kostopoulos <athanasios@akostopoulos.com>"

#ESTIMATORS = ["agglnse", "agglpse", "apsnse", "apspse", "file"]
#OPTIMIZERS = ["none", "brute_fast", "brute", "genetic"]
#FITNESS_FUNCTIONS = ["modularity"]

#WIDTH = 48
#HEIGHT = 32

import importlib
from binaryninja.plugin import PluginCommand


def generate_REcover_graphs(papari):
   print("lol")


def process_REcover_graphs(papari):
    print("yeah, right")

PluginCommand.register("REcover\\generate_graphs", "Generate Graphs to be used with REcover", generate_REcover_graphs)
PluginCommand.register("REcover\\process_graphs", "Process Graphs generated for REcover", process_REcover_graphs)
