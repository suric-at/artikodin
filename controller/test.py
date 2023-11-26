
try:
  print('try')
  raise Exception('raise')
except:
  print('except')
  raise
finally:
  print('allo')
