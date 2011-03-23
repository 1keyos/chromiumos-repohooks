def main(project_list, **kwargs):
  print ('These projects will be uploaded: %s' %
         ', '.join(project_list))
  print ('I am being a good boy and ignoring anything in kwargs\n'
         'that I don\'t understand.')
  print 'I fail 50% of the time.  How flaky.'
  if random.random() <= .5:
    raise Exception('Pre-upload hook failed.  Have a nice day.')

if __name__ == '__main__':                                                       
  main()    
