module soup_aux
  use soup
  use iso_c_binding

  implicit none

  private

  public &
       soup_aux_message_headers_get_one, &
       soup_aux_message_new, &
       soup_aux_session_request

  interface
     pure function strlen(s) bind(c)
       use iso_c_binding, only: c_size_t, c_ptr
       type(c_ptr), value :: s
       integer(c_size_t) strlen
     end function strlen
  end interface

contains

  function soup_aux_message_headers_get_one(hdrs, name)
    type(c_ptr), value :: hdrs
    character(*), intent(in) :: name
    character(:), allocatable :: soup_aux_message_headers_get_one

    character(:), allocatable, target :: buffer
    type(c_ptr) cptr

    buffer = name // char(0)
    cptr = soup_message_headers_get_one(hdrs, c_loc(buffer))

    block
      character(strlen(cptr)), pointer :: fptr
      call c_f_pointer(cptr, fptr)
      soup_aux_message_headers_get_one = fptr
    end block
  end function soup_aux_message_headers_get_one

  function soup_aux_message_new(method, uri_string)
    character(*), intent(in) :: method, uri_string
    type(c_ptr) soup_aux_message_new

    character(:), allocatable, target :: method_buffer, uri_buffer

    method_buffer = method // char(0)
    uri_buffer = uri_string // char(0)
    soup_aux_message_new = &
         soup_message_new(c_loc(method_buffer), c_loc(uri_buffer))
  end function soup_aux_message_new

  function soup_aux_session_request(session, uri_string)
    type(c_ptr), value :: session
    character(*), intent(in) :: uri_string
    type(c_ptr) soup_aux_session_request

    character(:), allocatable, target :: buffer

    buffer = uri_string // char(0)
    soup_aux_session_request = &
         soup_session_request(session, c_loc(buffer), c_null_ptr)
  end function soup_aux_session_request

end module soup_aux
