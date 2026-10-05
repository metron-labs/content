Refreshes the BloodHound Enterprise risk block on the open User, Computer, or Group indicator.

The script calls `bloodhound-principal-impact-get` with `view=risk` and writes the header, direct attack paths, and colored domain grid to the `bloodhoundriskdetails` indicator field. A failed lookup leaves the field unchanged.
