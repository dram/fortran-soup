program main
  use iso_c_binding
  use soup
  use soup_aux

  implicit none

  block
    type(c_ptr) session, request, stream

    session = soup_session_sync_new()
    request = soup_aux_session_request(session, 'http://www.example.com')
    stream = soup_request_send(request, c_null_ptr, c_null_ptr)
    print *, soup_request_get_content_length(request)
  end block

end program main
