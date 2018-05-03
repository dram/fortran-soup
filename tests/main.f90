program main
  use iso_c_binding
  use soup
  use soup_aux

  implicit none

  block
    integer(c_int) rc
    type(c_ptr) message, session, request, stream

    session = soup_session_sync_new()
    request = soup_aux_session_request(session, 'http://www.example.com')
    stream = soup_request_send(request, c_null_ptr, c_null_ptr)
    print *, soup_request_get_content_length(request)

    session = soup_session_sync_new()
    message = soup_aux_message_new('GET', 'http://www.example.com')
    rc = soup_session_send_message(session, message)
    print *, rc
  end block

end program main
