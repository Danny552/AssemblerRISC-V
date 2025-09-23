cadena = "lol luyu: # esto es un comentario"
print(type(cadena.split("#")[0]))
print(cadena.split("#")[0])

print(type(cadena.split("#")[0].strip()))
print(cadena.split("#")[0].strip())

if " " in cadena.split("#")[0].strip():
    print("Hay espacio")
else:
    print("No hay espacio")

print(type(cadena.split("#")[0].strip().split()))
print(cadena.split("#")[0].strip().split())
print(len(cadena.split("#")[0].strip().split()))