from cx_Freeze import setup, Executable

setup(name = "debloat" ,
      version = "0.1" ,
      description = "" ,
      executables = [Executable("debloat.py")])
