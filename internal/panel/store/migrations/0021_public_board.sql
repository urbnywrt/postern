-- The public page as a departure board: a footer of the page (plain text, the
-- default text when empty) and a code for every item, 0 to 4 letters and
-- digits in upper case (the country of the server when empty).

ALTER TABLE public_page ADD COLUMN footer TEXT NOT NULL DEFAULT '';

ALTER TABLE public_page_items ADD COLUMN code TEXT NOT NULL DEFAULT '';
