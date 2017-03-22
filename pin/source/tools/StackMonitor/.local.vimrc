nnoremap <F4> :make<CR>

if expand('%:t') == "StackMonitor.cpp"
    let b:pin="/usr/bin/tar -xf ./sipcrack.tgz"
    nnoremap <F5> :!clear && /home/spowell/research/pyitrace/pin/pin -t ./obj-intel64/StackMonitor.so -- <c-r><c-r>=b:pin<CR><CR>
elseif expand('%:t') == "server.c"
    :set makeprg=gcc\ server.c\ -o\ server
    nnoremap <F5> :!clear && ./server<CR>
endif
