module soup_aux
  use soup
  use iso_c_binding

  implicit none

  private

  public &
       soup_aux_session_request

  interface
     pure function strlen(s) bind(c)
       use iso_c_binding, only: c_size_t, c_ptr
       type(c_ptr), value :: s
       integer(c_size_t) strlen
     end function strlen
  end interface

contains

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
