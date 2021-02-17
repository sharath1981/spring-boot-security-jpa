package com.kpt.springbootsecurityjpa.service;

import com.kpt.springbootsecurityjpa.domain.UserDetailsImpl;
import com.kpt.springbootsecurityjpa.repository.UserRepository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUserName(username)
                             .map(UserDetailsImpl::new)
                             .orElseThrow(()->new UsernameNotFoundException(String.format("%s doesn't exists...", username)));
    }
    
}
