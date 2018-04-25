program main
  use iso_c_binding
  use soup
  use soup_aux

  implicit none

  block
    type(c_ptr) session, request

    session = soup_session_new()
    request = soup_aux_session_request(session, 'http://www.example.com')
  end block

end program main
