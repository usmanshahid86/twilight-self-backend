SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

--
-- Name: address; Type: TABLE; Schema: public; Owner: forkscanner
--
Create database zkpass;

\c zkpass

CREATE TABLE public.zkpass (
    address text NOT NULL,
    identifier text NOT NULL,
    provider text NOT NULL,
);


ALTER TABLE public.zkpass OWNER TO zkpass;